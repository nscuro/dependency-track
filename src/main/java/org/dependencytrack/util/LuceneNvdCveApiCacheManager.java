/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Steve Springett. All Rights Reserved.
 */
package org.dependencytrack.util;

import alpine.Config;
import alpine.common.logging.Logger;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.github.jeremylong.openvulnerability.client.nvd.CveApiJson20;
import io.github.jeremylong.openvulnerability.client.nvd.CveItem;
import io.github.jeremylong.openvulnerability.client.nvd.DefCveItem;
import net.jcip.annotations.NotThreadSafe;
import org.apache.lucene.analysis.Analyzer;
import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.DateTools.Resolution;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field;
import org.apache.lucene.document.SortedDocValuesField;
import org.apache.lucene.document.StoredField;
import org.apache.lucene.document.StringField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.index.Term;
import org.apache.lucene.queryparser.classic.MultiFieldQueryParser;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.MatchAllDocsQuery;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.Sort;
import org.apache.lucene.search.SortField;
import org.apache.lucene.search.TermQuery;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.search.TopFieldDocs;
import org.apache.lucene.store.FSDirectory;
import org.apache.lucene.util.BytesRef;

import java.io.IOException;
import java.nio.file.Path;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Date;

import static java.util.Objects.requireNonNull;
import static org.apache.lucene.document.DateTools.dateToString;

/**
 * @since 4.10.1
 */
@NotThreadSafe
public class LuceneNvdCveApiCacheManager implements AutoCloseable {

    public enum Mode {
        READ_ONLY,
        READ_WRITE
    }

    public static final class ApiParameters {

        private ZonedDateTime lastModStartDate;
        private ZonedDateTime lastModEndDate;
        private Integer resultsPerPage;
        private Integer startIndex;

        public ApiParameters withLastModStartDate(final ZonedDateTime lastModStartDate) {
            this.lastModStartDate = lastModStartDate;
            return this;
        }

        public ApiParameters withLastModEndDate(final ZonedDateTime lastModEndDate) {
            this.lastModEndDate = lastModEndDate;
            return this;
        }

        public ApiParameters withResultsPerPage(final Integer resultsPerPage) {
            this.resultsPerPage = resultsPerPage;
            return this;
        }

        public ApiParameters withStartIndex(final Integer startIndex) {
            this.startIndex = startIndex;
            return this;
        }

        private boolean hasLastModifiedFilter() {
            return lastModStartDate != null && lastModEndDate != null;
        }

        private String indexableLastModStartDate() {
            return lastModStartDate != null
                    ? dateToString(Date.from(lastModStartDate.toInstant()), Resolution.SECOND)
                    : null;
        }

        private String indexableLastModifiedEndDate() {
            return lastModStartDate != null
                    ? dateToString(Date.from(lastModEndDate.toInstant()), Resolution.SECOND)
                    : null;
        }

        private int resultsPerPage() {
            return resultsPerPage != null ? resultsPerPage : 2000;
        }

        private int startIndex() {
            return startIndex != null ? startIndex : 0;
        }

        private int maxResults() {
            return startIndex() + resultsPerPage();
        }

    }

    private static final Path CACHE_DIRECTORY_PATH = Config.getInstance().getDataDirectorty().toPath().resolve("index/nvdcve");
    private static final String FIELD_CVE_ID = "cveId";
    private static final String FIELD_CVE_ITEM = "cveItem";
    private static final String FIELD_LAST_MODIFIED = "lastModified";
    private static final String FIELD_PUBLISHED = "published";
    private static final int INDEX_COMMIT_THRESHOLD = 1000;
    private static final Logger LOGGER = Logger.getLogger(LuceneNvdCveApiCacheManager.class);
    private static final Sort SORT_PUBLISHED = new Sort(SortField.FIELD_SCORE, new SortField(FIELD_PUBLISHED, SortField.Type.STRING));

    private final FSDirectory cacheDirectory;
    private final Analyzer indexAnalyzer;
    private final IndexWriter indexWriter;
    private final IndexReader indexReader;
    private final IndexSearcher indexSearcher;
    private final QueryParser queryParser;
    private final ObjectMapper objectMapper;
    private int commitCount = 0;

    private LuceneNvdCveApiCacheManager(final FSDirectory cacheDirectory, final Analyzer indexAnalyzer,
                                        final IndexWriter indexWriter, final IndexReader indexReader) {
        this.cacheDirectory = requireNonNull(cacheDirectory);
        this.indexAnalyzer = requireNonNull(indexAnalyzer);
        this.indexWriter = indexWriter;
        this.indexReader = requireNonNull(indexReader);
        this.indexSearcher = new IndexSearcher(indexReader);
        this.queryParser = new MultiFieldQueryParser(new String[]{FIELD_CVE_ID, FIELD_LAST_MODIFIED, FIELD_PUBLISHED}, indexAnalyzer);
        this.objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());
    }

    /**
     * Create a new {@link LuceneNvdCveApiCacheManager} instance using a given {@link Mode}.
     *
     * @param mode The {@link Mode} to use
     * @return A new {@link LuceneNvdCveApiCacheManager} instance
     * @throws IOException When creation of the instance failed
     */
    public static LuceneNvdCveApiCacheManager create(final Mode mode) throws IOException {
        final var cacheDirectory = FSDirectory.open(CACHE_DIRECTORY_PATH);
        final var indexAnalyzer = new StandardAnalyzer();

        final IndexWriter indexWriter;
        final IndexReader indexReader;
        if (mode == Mode.READ_WRITE) {
            final var cacheIndexConfig = new IndexWriterConfig(indexAnalyzer)
                    .setOpenMode(IndexWriterConfig.OpenMode.CREATE_OR_APPEND)
                    .setCommitOnClose(true);

            indexWriter = new IndexWriter(cacheDirectory, cacheIndexConfig);
            indexReader = DirectoryReader.open(indexWriter);
        } else {
            indexWriter = null;
            indexReader = DirectoryReader.open(cacheDirectory);
        }

        return new LuceneNvdCveApiCacheManager(cacheDirectory, indexAnalyzer, indexWriter, indexReader);
    }

    /**
     * Creates or updates a {@link CveItem} record in the cache.
     *
     * @param cveItem The {@link CveItem} to cache
     * @throws IOException When updating the cache failed
     */
    public void addCve(final CveItem cveItem) throws IOException {
        if (indexWriter == null) {
            throw new IllegalStateException("Cannot add CVE because the index is opened in %s mode".formatted(Mode.READ_ONLY));
        }

        final Document document = createDocument(cveItem);

        final var cveIdTerm = new Term(FIELD_CVE_ID, cveItem.getId());
        final TopDocs searchResult = indexSearcher.search(new TermQuery(cveIdTerm), 1);
        if (searchResult.totalHits.value == 0) {
            LOGGER.debug("Creating document for %s".formatted(cveItem.getId()));
            indexWriter.addDocument(document);
        } else {
            LOGGER.debug("Updating document for %s".formatted(cveItem.getId()));
            indexWriter.updateDocument(cveIdTerm, document);
        }

        if (++commitCount >= INDEX_COMMIT_THRESHOLD) {
            indexWriter.commit();
            commitCount = 0;
        }
    }

    /**
     * Generate a {@link CveApiJson20} response based on data in the cache.
     *
     * @param apiParameters The API parameters to generate a response for
     * @return A generated {@link CveApiJson20} instance
     * @throws IOException When accessing the cache or deserializing records failed
     */
    public CveApiJson20 getApiResponseFromCache(final ApiParameters apiParameters) throws IOException {
        final int totalResults;
        final TopFieldDocs topDocs;
        if (apiParameters.hasLastModifiedFilter()) {
            final Query query;
            try {
                query = queryParser.parse("%s:[%s TO %s]".formatted(FIELD_LAST_MODIFIED,
                        apiParameters.indexableLastModStartDate(), apiParameters.indexableLastModifiedEndDate()));
            } catch (ParseException e) {
                throw new IOException("Parsing of the Lucene query failed", e);
            }
            topDocs = indexSearcher.search(query, apiParameters.resultsPerPage(), SORT_PUBLISHED);
            totalResults = Math.toIntExact(indexSearcher.search(query, indexReader.maxDoc()).totalHits.value);
        } else {
            topDocs = indexSearcher.search(new MatchAllDocsQuery(), apiParameters.maxResults(), SORT_PUBLISHED);
            totalResults = Math.toIntExact(indexSearcher.search(new MatchAllDocsQuery(), indexReader.maxDoc()).totalHits.value);
        }

        // There is no concept of offsets in Lucene, but searches return only very slim pointers
        // to the actual matched documents. So it's fine to emulate offsets by simply skipping the first
        // N search results.
        final var cveItems = new ArrayList<CveItem>();
        for (int i = apiParameters.startIndex(); i < topDocs.totalHits.value; i++) {
            if (i > apiParameters.maxResults() - 1) {
                break;
            }

            final Document doc = indexReader.document(topDocs.scoreDocs[i].doc);
            final IndexableField cveItemField = doc.getField(FIELD_CVE_ITEM);
            if (cveItemField == null) {
                continue;
            }

            cveItems.add(objectMapper.readValue(cveItemField.binaryValue().bytes, CveItem.class));
        }

        return new CveApiJson20(apiParameters.resultsPerPage(), apiParameters.startIndex(), totalResults,
                "NVD_CVE", "2.0", ZonedDateTime.now(), cveItems.stream().map(DefCveItem::new).toList());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void close() throws IOException {
        indexReader.close();
        if (indexWriter != null) {
            indexWriter.close();
        }
        indexAnalyzer.close();
        cacheDirectory.close();
    }

    private Document createDocument(final CveItem cveItem) throws IOException {
        final var publishedDate = Date.from(cveItem.getPublished().toInstant());
        final var lastModifiedDate = Date.from(cveItem.getLastModified().toInstant());
        final var indexablePublishedDate = dateToString(publishedDate, Resolution.SECOND);
        final var indexableLastModifiedDate = dateToString(lastModifiedDate, Resolution.SECOND);

        final var document = new Document();
        document.add(new StringField(FIELD_CVE_ID, cveItem.getId(), Field.Store.YES));
        document.add(new StoredField(FIELD_CVE_ITEM, objectMapper.writeValueAsBytes(cveItem)));
        document.add(new StringField(FIELD_LAST_MODIFIED, indexableLastModifiedDate, Field.Store.YES));
        document.add(new SortedDocValuesField(FIELD_LAST_MODIFIED, new BytesRef(indexableLastModifiedDate)));
        document.add(new StringField(FIELD_PUBLISHED, indexablePublishedDate, Field.Store.YES));
        document.add(new SortedDocValuesField(FIELD_PUBLISHED, new BytesRef(indexablePublishedDate)));

        return document;
    }

}
