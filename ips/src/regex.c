/**
 * @file regex.c
 * @brief IPS 시그니처 및 정규식 정의 테이블
 */
#include "regex.h"
#include <stddef.h>

#define PRIO_CRITICAL 5
#define PRIO_ERROR 4
#define PRIO_WARNING 3
#define PRIO_NOTICE 2

#define IPS_CTX_DEFAULT(pid) \
    ((pid) == POLICY_DIRECTORY_TRAVERS ? IPS_CTX_REQUEST_URI : \
     (pid) == POLICY_PROTOCOL_VIOLATION ? IPS_CTX_REQUEST_HEADERS : \
     (pid) == POLICY_INFO_LEAK ? IPS_CTX_REQUEST_BODY : \
     (pid) == POLICY_WEBSHELL ? IPS_CTX_REQUEST_BODY : \
     (pid) == POLICY_APP_WEAK ? IPS_CTX_REQUEST_HEADERS : \
     (pid) == POLICY_SCANNER ? IPS_CTX_REQUEST_URI : \
     (pid) == POLICY_XSS ? IPS_CTX_REQUEST_BODY : \
     IPS_CTX_ARGS)

#define SIG(pid, pname, pat, prio) \
    { (pid), (pname), (pat), (prio), IPS_CTX_DEFAULT(pid) }

const IPS_Signature g_ips_signatures[] = {
    /*--------------------------- SQL INJECTION ---------------------------*/
    SIG(POLICY_SQL_INJECTION     , "SQL_INJECTION"      , "(?:sleep\\s*?\\(.*?\\)|benchmark\\s*?\\(.*?,.*?\\))", PRIO_ERROR   ),
    SIG(POLICY_SQL_INJECTION     , "SQL_INJECTION"      , "(?:select|;)[\\s\\x0b]+(?:benchmark|if|sleep)[\\s\\x0b]*?\\([\\s\\x0b]*?\\(?[\\s\\x0b]*?[0-9A-Z_a-z]+", PRIO_ERROR   ),
    SIG(POLICY_SQL_INJECTION     , "SQL_INJECTION"      , "merge.*?using\\s*?\\(|execute\\s*?immediate\\s*?[\"'`]|match\\s*?[\\w(),+-]+\\s*?against\\s*?\\(", PRIO_NOTICE  ),
    SIG(POLICY_SQL_INJECTION     , "SQL_INJECTION"      , "union.*?select.*?from", PRIO_CRITICAL),
    SIG(POLICY_SQL_INJECTION     , "SQL_INJECTION"      , "/\\*[\\s\\x0b]*?[!\\+](?:[\\s\\x0b\\(\\)\\-0-9=A-Z_a-z]+)?\\*/", PRIO_NOTICE  ),
    SIG(POLICY_SQL_INJECTION     , "SQL_INJECTION"      , "^(?:[^']*'|[^\"]*\"|[^`]*`)[\\s\\x0b]*;", PRIO_NOTICE  ),
    SIG(POLICY_SQL_INJECTION     , "SQL_INJECTION"      , "1\\.e(?:[\\(\\),]|\\.[\\$0-9A-Z_a-z])", PRIO_NOTICE  ),
    SIG(POLICY_SQL_INJECTION     , "SQL_INJECTION"      , "/\\*!?|\\*/|[';]--|--(?:[\\s\\x0b]|[^\\-]*?-)|[^&\\-]#.*?[\\s\\x0b]|;?\\x00", PRIO_NOTICE  ),
    SIG(POLICY_SQL_INJECTION     , "SQL_INJECTION"      , "(?:\\b0x[a-f\\d]{3,}|x\\'[a-f\\d]{3,}\\'|b\\'[0-1]{10,}\\')", PRIO_NOTICE  ),
    /*--------------------------- XSS ---------------------------*/
    SIG(POLICY_XSS               , "XSS"                , "(?i)<script[^>]*>[\\s\\S]*?", PRIO_CRITICAL),
    SIG(POLICY_XSS               , "XSS"                , "(?i)[\\s\\\"'`;/0-9=\\x0B\\x09\\x0C\\x3B\\x2C\\x28\\x3B]on[a-zA-Z]{3,50}[\\s\\x0B\\x09\\x0C\\x3B\\x2C\\x28\\x3B]*?=[^=]", PRIO_CRITICAL),
    SIG(POLICY_XSS               , "XSS"                , "(?i)[a-z]+=(?:[^:=]+:.+;)*?[^:=]+:url\\(javascript", PRIO_ERROR   ),
    SIG(POLICY_XSS               , "XSS"                , "(?i)<style.*?>.*?(?:@[\\x5ci]|(?:[:=]|&#x?0*(?:58|3[AD]|61);?).*?(?:[\\(\\x5c]|&#x?0*(?:40|28|92|5C);?))", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "(?i:<.*[:]?vmlframe.*?[\\s/+]*?src[\\s/+]*=)", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "(?i)<EMBED[\\s/+].*?(?:src|type).*?=", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "<[?]?import[\\s/+\\S]*?implementation[\\s/+]*?=", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "(?i)<META[\\s/+].*?charset[\\s/+]*=", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "(?i)<LINK[\\s/+].*?href[\\s/+]*=", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "(?i)<BASE[\\s/+].*?href[\\s/+]*=", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "(?i)<APPLET[\\s/+>]", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "(?i)<OBJECT[\\s/+].*?(?:type|codetype|classid|code|data)[\\s/+]*=", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "\\xbc[^\\xbe>]*[\\xbe>]|<[^\\xbe]*\\xbe", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "(?:\\xbc\\s*/\\s*[^\\xbe>]*[\\xbe>])|(?:<\\s*/\\s*[^\\xbe]*\\xbe)", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "\\+ADw-.*(?:\\+AD4-|>)|<.*\\+AD4-", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "![!+ ]\\[\\]", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "(?:self|document|this|top|window)\\s*(?:/\\*|[\\[)]).+?(?:\\]|\\*/)", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "((?:\\[[^\\]]*\\][^.]*\\.)|Reflect[^.]*\\.).*(?:map|sort|apply)[^.]*\\..*call[^`]*`.*`", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "(?i)\\b(?:s(?:tyle|rc)|href)\\b[\\s\\S]*?=", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "(?i)[\\\"'][ ]*(?:[^a-z0-9~_:\\' ]|in).+?[.].+?=", PRIO_NOTICE  ),
    SIG(POLICY_XSS               , "XSS"                , "\\{\\{.*?\\}\\}", PRIO_NOTICE  ),

    /*--------------------------- GENERIC ---------------------------*/
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "__proto__|constructor[\\s\\x0b]*(?:\\.|\\]?\\[)[\\s\\x0b]*prototype", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "Process[\\s\\x0b]*\\.[\\s\\x0b]*spawn[\\s\\x0b]*\\(", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?:close|exists|fork|(?:ope|spaw)n|re(?:ad|quire)|w(?:atch|rite))[\\s\\x0b]*\\(", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "@+\\{[\\s\\x0b]*\\[", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?:\\{%[^%}]*%}|<%=?[^%>]*%>)", PRIO_NOTICE  ),
    /*--------------------------- CRS CONF @RX ---------------------------*/
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "~[\\+\\-](?:$|[0-9]+)", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "\\{[0-9A-Z_a-z]*,[,\\-0-9A-Z_a-z]*\\}", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "!-\\d", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "^\\(\\s*\\)\\s+\\{", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "^\\(\\s*\\)\\s+\\{", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?i)(?:\\.boto|buddyinfo|mtrr|acpi|zoneinfo)\\B", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "['\\*\\?\\x5c`][^\\n/]+/|/[^/]+?['\\*\\?\\x5c`]|\\$[!#\\$\\(\\*\\-0-9\\?-\\[_a-\\{]", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "#.*", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "['\\*\\?\\x5c`][^\\n/]+/|/[^/]+?['\\*\\?\\x5c`]|\\$[!#\\$\\(\\*\\-0-9\\?-\\[_a-\\{]", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "[0-9]\\s*\\'\\s*[0-9]", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "\\{[^\\s\\x0b,:\\}]*,[^\\s\\x0b]*\\}", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "~[0-9]+", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?i)/(?:[\\*\\?]+[/-9A-Z_a-z]|[/-9A-Z_a-z]+[\\*\\?])", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "\\r\\n.*?\\b(?:DATA|QUIT|HELP(?: .{1,255})?)", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "\\r\\n.*?\\b(?:(?:QUI|STA|RSE)T|NOOP|CAPA)", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "!(?:\\d|!)", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?i)<\\?(?:php[\\s\\x0b]|[\\s\\x0b=]|xml(?:[\\s\\x0b]+[^a-z]|:)|$)|\\[[/\\x5c]?php\\]|\\{/?php\\}", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , ".*\\.ph(?:p\\d*|tml|ar|ps|t|pt)\\.*$", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "\\$\\s*\\{\\s*\\S[^\\{\\}]*\\}", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?i)php://(?:std(?:in|out|err)|(?:in|out)put|fd|memory|temp|filter)", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?:bzip2|expect|glob|ogg|(?:ph|r)ar|ssh2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?|z(?:ip|lib))://", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "[oOcC]:\\d+:\\\".+?\\\":\\d+:\\{.*}", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?:^|[/\\x5c])sess_[,\\-0-9a-z]{20,256}$", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , ".*\\.ph(?:p\\d*|tml|ar|ps|t|pt)\\..*$", PRIO_NOTICE  ),
    SIG(POLICY_APP_WEAK          , "APP_WEAK"           , "(?i:\\.cookie\\b.*?;\\W*?(?:expires|domain)\\W*?=|\\bhttp-equiv\\W+set-cookie\\b)", PRIO_NOTICE  ),
    SIG(POLICY_APP_WEAK          , "APP_WEAK"           , "^(?:ht|f)tps?://(.*?)/", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "java\\.lang\\.(?:runtime|processbuilder)", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?:runtime|processbuilder)", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?i)(?:unmarshaller|base64data|java\\.)", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?:runtime|processbuilder)", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , ".*\\.(?:jsp|jspx)\\.*$", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "\\xac\\xed\\x00\\x05", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?:rO0ABQ|KztAAU|Cs7QAF)", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "java\\b.+(?:runtime|processbuilder)", PRIO_NOTICE  ),
    SIG(POLICY_COMMAND_INJECTION , "COMMAND_INJECTION"  , "(?i)(?:\\$|&dollar;?)(?:\\{|&l(?:brace|cub);?)", PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?:<(?:TITLE>Index of.*?<H|title>Index of.*?<h)1>Index of|>\\[To Parent Directory\\]</[Aa]><br>)", PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "^#\\!\\s?/", PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "^5\\d{2}$", PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)(?:JET|Access) Database Engine|\\[Microsoft\\]\\[ODBC Microsoft Access Driver\\]", PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)DB2 SQL error|\\[IBM\\]\\[CLI Driver\\]\\[DB2/6000\\]|CLI Driver.*DB2|db2_[0-9A-Z_a-z]+\\(\\)", PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)\\[DM_QUERY_E_SYNTAX\\]|has occurred in the vicinity of:", PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)Dynamic SQL Error",  PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)Exception (?:condition )?\\d+\\. Transaction rollback\\.", PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)org\\.hsqldb\\.jdbc", PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)An illegal character has been found in the statement|com\\.informix\\.jdbc|Exception.*Informix", PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)Warning.*ingres_|Ingres(?: SQLSTATE|[^0-9A-Z_a-z].*Driver)",     PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)<b>Warning</b>: ibase_|Unexpected end of command in statement",  PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)Warning.{1,10}maxdb[\\(\\):_a-z]{1,26}:",    PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)Sybase(?: message:|.*Server message)|Warning.{2,20}sybase",      PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)<\\?(?:=|php)?\\s+",                         PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)[a-z]:[\\x5c/]inetpub\\b",                   PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "^404$",                                          PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "\\bServer Error in.{0,50}?\\bApplication\\b",    PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)[\\x5c/]inetpub\\b",                         PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "<title>r57 Shell Version [0-9.]+</title>|<title>r57 shell</title>",  PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "B4TM4N SH3LL</title>[^<]*<meta name='author' content='k4mpr3t'/>",   PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "<title>Mini Shell</title>[^D]*Developed By LameHacker",          PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "<title>\\.:: [^~]*~ Ashiyane V [0-9.]+ ::\\.</title>",           PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "<title>Symlink_Sa [0-9.]+</title>",                              PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "<title>CasuS [0-9.]+ by MafiABoY</title>",                       PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "^<html>\\r\\n<head>\\r\\n<title>GRP WebShell [0-9.]+",           PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "<small>NGHshell [0-9.]+ by Cr4sh</body></html>\\n$",             PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "<title>SimAttacker - (?:Version|Vrsion) : [0-9.]+ -",            PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "^<!DOCTYPE html>\\n<html>\\n<!-- By Artyum [^<]*<title>Web Shell</title>", PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "<title>lama's'hell v. [0-9.]+</title>",                          PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "^ *<html>\\n[ ]+<head>\\n[ ]+<title>lostDC -",                   PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "^<title>PHP Web Shell</title>\\r\\n<html>\\r\\n<body>\\r\\n    <!-- Replaces command with Base64-encoded Data -->", PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "^<html>\\n<head>\\n<title>Ru24PostWebShell",                     PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "<title>s72 Shell v[0-9.]+ Codinf by Cr@zy_King</title>",         PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "^<html>\\r\\n<head>\\r\\n<meta http-equiv=\\\"Content-Type\\\" content=\\\"text/html; charset=gb2312\\\">\\r\\n<title>PhpSpy Ver [0-9]+</title>", PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "^ <html>\\n\\n<head>\\n\\n<title>g00nshell v[0-9.]+",            PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "^<html>\\n      <head>\\n             <title>azrail [0-9.]+ by C-W-M</title>", PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , ">SmEvK_PaThAn Shell v[0-9]+ coded by <a href=",                  PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "^<html>\\n<title>[^~]*~ Shell I</title>\\n<head>\\n<style>",     PRIO_NOTICE  ),
    SIG(POLICY_WEBSHELL          , "WEBSHELL"           , "^ <html><head><title>:: b374k m1n1 [0-9.]+ ::</title>",          PRIO_NOTICE  ),
    SIG(POLICY_INFO_LEAK         , "INFO_LEAK"          , "(?i)(?:<%[=#\\s]|#\\{[^}]+\\})",                                 PRIO_NOTICE  ),

    /*--------------------------- PROTOCOL ---------------------------*/
    SIG(POLICY_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION" , "[\\n\\r][^0-9A-Z_a-z]*?(?:content-(?:type|length)|set-cookie|location):[\\s\\x0b]*[0-9A-Z_a-z]", PRIO_NOTICE  ),
    SIG(POLICY_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION" , "(?:\\bhttp/\\d|<(?:html|meta)\\b)",      PRIO_NOTICE  ),
    SIG(POLICY_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION" , "unix:[^|]*\\|",                          PRIO_NOTICE  ),
    SIG(POLICY_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION" , "(][^\\]]+$|][^\\]]+\\[)",                PRIO_NOTICE  ),
    SIG(POLICY_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION" , "\\[",                                    PRIO_NOTICE  ),
    /*--------------------------- MULTIPART ---------------------------*/
    SIG(POLICY_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION" , "^content-type\\s*:\\s*(.*)$",                PRIO_NOTICE  ),
    SIG(POLICY_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION" , "content-transfer-encoding:(.*)",             PRIO_NOTICE  ),
    SIG(POLICY_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION" , "[^\\x21-\\x7E][\\x21-\\x39\\x3B-\\x7E]*:",   PRIO_NOTICE  ),

    /*--------------------------- LFI / PATH TRAVERSAL ---------------------------*/
    SIG(POLICY_DIRECTORY_TRAVERS , "DIRECTORY_TRAVERSAL", "(?:^|[/;\\x5c])\\.{2,3}[/;\\x5c]", PRIO_NOTICE  ),
};

const int g_signature_count = (int)(sizeof(g_ips_signatures) / sizeof(g_ips_signatures[0]));

const char *get_policy_name(POLICY p)
{
    static const char *policy_names[] = {
#define X(ename, sname) [ename] = sname,
        POLICY_LIST
#undef X
    };

    if ((int)p < 0 || p >= POLICY_MAX)
    {
        return "UNKNOWN_POLICY";
    }

    return policy_names[p] ? policy_names[p] : "UNDEFINED_NAME";
}
