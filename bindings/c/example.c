#include "basecrawl.h"

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  const char *url = argc > 1 ? argv[1] : "https://example.com";
  const char *options_json = NULL;
  char options_buffer[128];
  if (argc > 2 && strcmp(argv[2], "--options") == 0) {
    if (argc != 4) {
      fputs("usage: basecrawl-c-example [URL] [FORMAT | --options JSON]\n", stderr);
      return 2;
    }
    options_json = argv[3];
  } else {
    const char *format = argc > 2 ? argv[2] : "rawHtml";
    int written = snprintf(
        options_buffer,
        sizeof(options_buffer),
        "{\"formats\":[\"%s\"],\"renderEnabled\":false}",
        format);
    if (written < 0 || written >= (int)sizeof(options_buffer)) {
      fputs("failed to encode C SDK options\n", stderr);
      return 2;
    }
    options_json = options_buffer;
  }

  char *proof = basecrawl_scrape_json(url, options_json);
  if (proof == NULL) {
    const char *error = basecrawl_last_error_json();
    fputs(error == NULL ? "{\"error\":{\"kind\":\"unknown\"}}\n" : error, stderr);
    fputc('\n', stderr);
    return 1;
  }

  puts(proof);
  basecrawl_free_string(proof);
  return 0;
}
