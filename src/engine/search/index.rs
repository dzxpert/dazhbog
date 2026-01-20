//! Full-text search index using Tantivy.

use super::types::{SearchDocument, SearchHit};
use std::{io, path::Path};
use tantivy::collector::TopDocs;

/// Extract only the filename from a path, stripping directories.
/// Handles both Unix (/) and Windows (\) path separators regardless of platform.
/// Prevents leaking usernames or directory structures in API responses.
fn sanitize_basename(input: &str) -> String {
    let input = input.trim();
    if input.is_empty() {
        return String::new();
    }

    // Find the last occurrence of either path separator
    let last_sep = input
        .rfind('/')
        .into_iter()
        .chain(input.rfind('\\'))
        .max();

    let base = match last_sep {
        Some(idx) => &input[idx + 1..],
        None => input,
    };

    let base = base.trim();
    if base.is_empty() {
        return String::new();
    }

    if base.len() > 255 {
        base[..255].to_string()
    } else {
        base.to_string()
    }
}
use tantivy::query::QueryParser;
use tantivy::schema::{Field, IndexRecordOption, Schema, TextFieldIndexing, TextOptions, STORED};
use tantivy::tokenizer::{LowerCaser, RawTokenizer, SimpleTokenizer, TextAnalyzer};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, Term};

/// Full-text search index for function metadata.
pub struct SearchIndex {
    index: Index,
    reader: IndexReader,
    writer: parking_lot::Mutex<IndexWriter>,
    fields: SearchFields,
}

struct SearchFields {
    key_hex: Field,
    func_name: Field,
    func_name_demangled: Field,
    lang: Field,
    binary_name: Field,
    ts: Field,
}

impl SearchIndex {
    /// Open or create a search index at the given directory.
    pub fn open(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;

        let schema = build_schema();
        let index = match Index::open_in_dir(dir) {
            Ok(idx) => idx,
            Err(_) => Index::create_in_dir(dir, schema.clone())
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("create index: {e}")))?,
        };

        register_tokenizers(&index);

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::Manual)
            .try_into()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("reader: {e}")))?;

        let writer = index
            .writer(50_000_000)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("writer: {e}")))?;

        let fields = SearchFields::load(&index.schema())?;

        Ok(Self {
            index,
            reader,
            writer: parking_lot::Mutex::new(writer),
            fields,
        })
    }

    /// Check if the index is empty.
    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.reader.searcher().num_docs() == 0)
    }

    /// Index a single function document (with immediate commit).
    /// For bulk operations, use `index_function_batch` instead.
    pub fn index_function(&self, doc: &SearchDocument) -> io::Result<()> {
        self.index_function_no_commit(doc)?;
        self.commit()
    }

    /// Index a single function document without committing.
    /// Call `commit()` after indexing a batch of documents.
    pub fn index_function_no_commit(&self, doc: &SearchDocument) -> io::Result<()> {
        let key_hex = format!("{:032x}", doc.key);
        let writer = self.writer.lock();
        writer.delete_term(Term::from_field_text(self.fields.key_hex, &key_hex));

        let mut tdoc = tantivy::Document::new();
        tdoc.add_text(self.fields.key_hex, &key_hex);
        tdoc.add_text(self.fields.func_name, &doc.func_name);
        tdoc.add_text(self.fields.func_name_demangled, &doc.func_name_demangled);
        tdoc.add_text(self.fields.lang, &doc.lang);
        tdoc.add_u64(self.fields.ts, doc.ts);
        for bn in &doc.binary_names {
            tdoc.add_text(self.fields.binary_name, bn);
        }
        writer
            .add_document(tdoc)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("add doc: {e}")))?;
        Ok(())
    }

    /// Commit pending changes and reload the reader.
    pub fn commit(&self) -> io::Result<()> {
        let mut writer = self.writer.lock();
        writer
            .commit()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("commit: {e}")))?;
        drop(writer);
        self.reader
            .reload()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("reload: {e}")))?;
        Ok(())
    }

    /// Delete a function from the index.
    pub fn delete(&self, key: u128) -> io::Result<()> {
        let key_hex = format!("{:032x}", key);
        let mut writer = self.writer.lock();
        writer.delete_term(Term::from_field_text(self.fields.key_hex, &key_hex));
        writer
            .commit()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("commit: {e}")))?;
        drop(writer);
        self.reader
            .reload()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("reload: {e}")))?;
        Ok(())
    }

    /// Rebuild the entire index from an iterator of documents.
    pub fn rebuild<I>(&self, docs: I) -> io::Result<()>
    where
        I: IntoIterator<Item = SearchDocument>,
    {
        let mut writer = self.writer.lock();
        writer.delete_all_documents().map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("search index delete_all_documents: {e}"),
            )
        })?;

        for doc in docs.into_iter() {
            let key_hex = format!("{:032x}", doc.key);
            let mut tdoc = tantivy::Document::new();
            tdoc.add_text(self.fields.key_hex, &key_hex);
            tdoc.add_text(self.fields.func_name, &doc.func_name);
            tdoc.add_text(self.fields.func_name_demangled, &doc.func_name_demangled);
            tdoc.add_text(self.fields.lang, &doc.lang);
            tdoc.add_u64(self.fields.ts, doc.ts);
            for bn in &doc.binary_names {
                tdoc.add_text(self.fields.binary_name, bn);
            }
            writer
                .add_document(tdoc)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("add doc: {e}")))?;
        }

        writer
            .commit()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("commit: {e}")))?;
        drop(writer);
        self.reader
            .reload()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("reload: {e}")))?;
        Ok(())
    }

    /// Search for functions matching the query. Returns up to `limit` results.
    pub fn search(&self, query: &str, limit: usize) -> io::Result<Vec<SearchHit>> {
        let query_str = query.trim();
        if query_str.is_empty() {
            return Ok(Vec::new());
        }

        let searcher = self.reader.searcher();

        // Build query parser for all indexed text fields
        let query_parser = QueryParser::for_index(
            &self.index,
            vec![
                self.fields.func_name,
                self.fields.func_name_demangled,
                self.fields.binary_name,
            ],
        );

        // Parse query - escape special chars and use lenient mode
        let tantivy_query = query_parser
            .parse_query_lenient(query_str)
            .0;

        // Execute search using the index
        let top_docs = searcher
            .search(&tantivy_query, &TopDocs::with_limit(limit))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("search: {e}")))?;

        let mut hits = Vec::with_capacity(top_docs.len());

        for (score, doc_addr) in top_docs {
            let doc = searcher
                .doc(doc_addr)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("fetch doc: {e}")))?;

            let key_hex = doc
                .get_first(self.fields.key_hex)
                .and_then(|v| v.as_text())
                .unwrap_or("")
                .to_string();

            let func_name = doc
                .get_first(self.fields.func_name)
                .and_then(|v| v.as_text())
                .unwrap_or("")
                .to_string();

            let func_name_demangled = doc
                .get_first(self.fields.func_name_demangled)
                .and_then(|v| v.as_text())
                .unwrap_or("")
                .to_string();

            let lang = doc
                .get_first(self.fields.lang)
                .and_then(|v| v.as_text())
                .unwrap_or("")
                .to_string();

            let binary_names: Vec<String> = doc
                .get_all(self.fields.binary_name)
                .filter_map(|v| v.as_text())
                .map(|s| sanitize_basename(s))
                .filter(|s| !s.is_empty())
                .collect();

            hits.push(SearchHit::new_with_demangled(
                key_hex,
                func_name,
                func_name_demangled,
                lang,
                binary_names,
                score,
            ));
        }

        Ok(hits)
    }

    /// Get the number of documents in the search index.
    pub fn doc_count(&self) -> u64 {
        self.reader.searcher().num_docs()
    }
}

fn build_schema() -> Schema {
    let mut builder = Schema::builder();

    // Symbol tokenizer: splits on :: . < > ( ) etc, then lowercases
    // This turns "gb::crepe::CacheTagParser::EndObject(int)" into
    // tokens: gb, crepe, cachetagparser, endobject, int
    let symbol_indexing = TextFieldIndexing::default()
        .set_tokenizer("symbol")
        .set_index_option(IndexRecordOption::WithFreqs);
    let symbol_options = TextOptions::default()
        .set_indexing_options(symbol_indexing)
        .set_stored();

    // Stored-only fields (no indexing, just for retrieval)
    let stored_only = TextOptions::default().set_stored();

    let key_options = TextOptions::default().set_stored().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer("raw")
            .set_index_option(IndexRecordOption::Basic),
    );

    builder.add_text_field("key_hex", key_options);
    builder.add_text_field("func_name", symbol_options.clone());
    builder.add_text_field("func_name_demangled", symbol_options.clone());
    builder.add_text_field("lang", stored_only);
    builder.add_text_field("binary_name", symbol_options);
    builder.add_u64_field("ts", STORED);

    builder.build()
}

fn register_tokenizers(index: &Index) {
    // Symbol tokenizer: SimpleTokenizer splits on non-alphanumeric chars
    // (handles ::, ., <>, (), etc.), then lowercase for case-insensitive search
    let symbol = TextAnalyzer::builder(SimpleTokenizer::default())
        .filter(LowerCaser)
        .build();
    let raw = TextAnalyzer::builder(RawTokenizer::default()).build();
    index.tokenizers().register("symbol", symbol);
    index.tokenizers().register("raw", raw);
}

impl SearchFields {
    fn load(schema: &Schema) -> io::Result<Self> {
        let key_hex = schema.get_field("key_hex").map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("key_hex field missing: {e}"))
        })?;
        let func_name = schema.get_field("func_name").map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("func_name field missing: {e}"),
            )
        })?;
        let func_name_demangled = schema.get_field("func_name_demangled").map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("func_name_demangled field missing: {e}"),
            )
        })?;
        let lang = schema.get_field("lang").map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("lang field missing: {e}"))
        })?;
        let binary_name = schema.get_field("binary_name").map_err(|e| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("binary_name field missing: {e}"),
            )
        })?;
        let ts = schema
            .get_field("ts")
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("ts field missing: {e}")))?;
        Ok(Self {
            key_hex,
            func_name,
            func_name_demangled,
            lang,
            binary_name,
            ts,
        })
    }
}
