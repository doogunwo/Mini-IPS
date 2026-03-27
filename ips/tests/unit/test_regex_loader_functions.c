#include "../../src/inline/regex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../common/unit_test.h"

#include "../../src/inline/regex.c"

static int write_file(const char *path, const char *content) {
    FILE *fp;

    fp = fopen(path, "w");
    if (NULL == fp) {
        return -1;
    }
    if (NULL != content) {
        fputs(content, fp);
    }
    fclose(fp);
    return 0;
}

static void cleanup_path(const char *path) {
    if (NULL != path) {
        unlink(path);
    }
}

static void cleanup_ruleset_dir(const char *dir) {
    char path[512];

    if (NULL == dir) {
        return;
    }

    snprintf(path, sizeof(path), "%s/sqli.jsonl", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/xss.jsonl", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/rce.jsonl", dir);
    unlink(path);
    snprintf(path, sizeof(path), "%s/directory_traversal.jsonl", dir);
    unlink(path);
    rmdir(dir);
}

int main(void) {
    char         file_template[] = "/tmp/ips_regex_file_XXXXXX";
    char         dir_template[]  = "/tmp/ips_regex_dir_XXXXXX";
    char         path[512];
    int          fd;
    char        *dir;
    regex_table_t table;
    regex_db_t    db;
    int           rc;

    memset(&table, 0, sizeof(table));
    fd = mkstemp(file_template);
    EXPECT_TRUE("mkstemp", "fd >= 0", fd >= 0);
    close(fd);
    EXPECT_INT_EQ("write_file", 0,
                  write_file(file_template,
                             "{\"name\":\"SQL_INJECTION\",\"pat\":\"pat-a\","
                             "\"ctx\":\"URI\",\"score\":10}\n"
                             "bad-line\n"
                             "{\"name\":\"SQL_INJECTION\",\"pat\":\"pat-b\","
                             "\"ctx\":\"HEADERS\",\"score\":20}\n"));

    rc = try_load_jsonl_file(&table, file_template);
    EXPECT_INT_EQ("try_load_jsonl_file", 0, rc);
    EXPECT_SIZE_EQ("try_load_jsonl_file", 2, table.count);
    EXPECT_STR_EQ("try_load_jsonl_file", "pat-a", table.items[0].pattern);
    EXPECT_INT_EQ("try_load_jsonl_file", 10, table.items[0].priority);
    EXPECT_INT_EQ("try_load_jsonl_file", 1, table.items[0].context);
    EXPECT_STR_EQ("try_load_jsonl_file", "pat-b", table.items[1].pattern);
    EXPECT_INT_EQ("try_load_jsonl_file", 20, table.items[1].priority);
    EXPECT_INT_EQ("try_load_jsonl_file", 2, table.items[1].context);
    for (size_t i = 0; i < table.count; i++) {
        free(table.items[i].pattern);
    }
    free(table.items);
    cleanup_path(file_template);

    dir = mkdtemp(dir_template);
    EXPECT_PTR_NOT_NULL("mkdtemp", dir);
    snprintf(path, sizeof(path), "%s/sqli.jsonl", dir);
    EXPECT_INT_EQ("write_file", 0,
                  write_file(path,
                             "{\"name\":\"SQL_INJECTION\",\"pat\":\"sqli-rule\","
                             "\"ctx\":\"URI\",\"score\":1}\n"));
    snprintf(path, sizeof(path), "%s/xss.jsonl", dir);
    EXPECT_INT_EQ("write_file", 0,
                  write_file(path,
                             "{\"name\":\"XSS\",\"pat\":\"xss-rule\","
                             "\"ctx\":\"HEADERS\",\"score\":2}\n"));
    snprintf(path, sizeof(path), "%s/rce.jsonl", dir);
    EXPECT_INT_EQ("write_file", 0,
                  write_file(path,
                             "{\"name\":\"RCE\",\"pat\":\"rce-rule\","
                             "\"ctx\":\"BODY\",\"score\":3}\n"));
    snprintf(path, sizeof(path), "%s/directory_traversal.jsonl", dir);
    EXPECT_INT_EQ("write_file", 0,
                  write_file(path,
                             "{\"name\":\"DIRECTORY_TRAVERSAL\","
                             "\"pat\":\"dt-rule\",\"ctx\":\"URI\","
                             "\"score\":4}\n"));

    memset(&db, 0, sizeof(db));
    rc = try_load_file(&db, dir);
    EXPECT_INT_EQ("try_load_file", 0, rc);
    EXPECT_SIZE_EQ("try_load_file", 1, db.sqli.count);
    EXPECT_SIZE_EQ("try_load_file", 1, db.xss.count);
    EXPECT_SIZE_EQ("try_load_file", 1, db.rce.count);
    EXPECT_SIZE_EQ("try_load_file", 1, db.directory_traversal.count);
    EXPECT_STR_EQ("try_load_file", "sqli-rule", db.sqli.items[0].pattern);
    EXPECT_STR_EQ("try_load_file", "xss-rule", db.xss.items[0].pattern);
    regex_signatures_free(&db);

    memset(&db, 0, sizeof(db));
    rc = regex_signatures_load(&db, dir);
    EXPECT_INT_EQ("regex_signatures_load", 0, rc);
    EXPECT_SIZE_EQ("regex_signatures_load", 1, db.sqli.count);
    EXPECT_SIZE_EQ("regex_signatures_load", 1, db.xss.count);
    EXPECT_SIZE_EQ("regex_signatures_load", 1, db.rce.count);
    EXPECT_SIZE_EQ("regex_signatures_load", 1, db.directory_traversal.count);
    EXPECT_STR_EQ("regex_signatures_load", "dt-rule",
                  db.directory_traversal.items[0].pattern);
    regex_signatures_free(&db);

    EXPECT_INT_EQ("regex_signatures_load", -1, regex_signatures_load(NULL, dir));
    EXPECT_INT_EQ("regex_signatures_load", -1, regex_signatures_load(&db, NULL));

    cleanup_ruleset_dir(dir);
    return 0;
}
