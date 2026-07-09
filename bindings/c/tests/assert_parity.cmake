set(EXAMPLE_OPTIONS [[{"formats":["markdown","links","metadata"],"renderEnabled":false}]])

execute_process(
  COMMAND "${PROGRAM}" "https://example.com" "--options" "${EXAMPLE_OPTIONS}"
  RESULT_VARIABLE c_example_result
  OUTPUT_VARIABLE c_example_proof
  ERROR_VARIABLE c_example_error
)
execute_process(
  COMMAND "${CLI}" "https://example.com"
    "--formats" "markdown,links,metadata" "--no-js" "--output" "json"
  RESULT_VARIABLE cli_example_result
  OUTPUT_VARIABLE cli_example_proof
  ERROR_VARIABLE cli_example_error
)

if(NOT c_example_result EQUAL 0)
  message(FATAL_ERROR "C SDK example.com scrape failed: ${c_example_error}")
endif()
if(NOT cli_example_result EQUAL 0)
  message(FATAL_ERROR "CLI example.com scrape failed: ${cli_example_error}")
endif()

string(JSON c_result_hash GET "${c_example_proof}" result result_hash)
string(JSON cli_result_hash GET "${cli_example_proof}" result result_hash)
if(NOT c_result_hash STREQUAL cli_result_hash)
  message(FATAL_ERROR "C SDK result_hash differs from CLI")
endif()

string(JSON c_cert_chain_hash GET "${c_example_proof}" tls cert_chain_hash)
string(JSON cli_cert_chain_hash GET "${cli_example_proof}" tls cert_chain_hash)
if(NOT c_cert_chain_hash STREQUAL cli_cert_chain_hash)
  message(FATAL_ERROR "C SDK cert_chain_hash differs from CLI")
endif()

set(QUOTE_OPTIONS [[{"formats":["markdown","links"],"renderEnabled":false}]])

execute_process(
  COMMAND "${PROGRAM}" "https://quotes.toscrape.com" "--options" "${QUOTE_OPTIONS}"
  RESULT_VARIABLE c_quotes_result
  OUTPUT_VARIABLE c_quotes_proof
  ERROR_VARIABLE c_quotes_error
)
execute_process(
  COMMAND "${CLI}" "https://quotes.toscrape.com"
    "--formats" "markdown,links" "--no-js" "--output" "json"
  RESULT_VARIABLE cli_quotes_result
  OUTPUT_VARIABLE cli_quotes_proof
  ERROR_VARIABLE cli_quotes_error
)

if(NOT c_quotes_result EQUAL 0)
  message(FATAL_ERROR "C SDK quotes scrape failed: ${c_quotes_error}")
endif()
if(NOT cli_quotes_result EQUAL 0)
  message(FATAL_ERROR "CLI quotes scrape failed: ${cli_quotes_error}")
endif()

string(JSON c_markdown GET "${c_quotes_proof}" result formats_produced markdown)
string(JSON cli_markdown GET "${cli_quotes_proof}" result formats_produced markdown)
if(NOT c_markdown STREQUAL cli_markdown)
  message(FATAL_ERROR "C SDK markdown differs from CLI")
endif()

string(JSON c_links GET "${c_quotes_proof}" result formats_produced links)
string(JSON cli_links GET "${cli_quotes_proof}" result formats_produced links)
if(NOT c_links STREQUAL cli_links)
  message(FATAL_ERROR "C SDK links content or order differs from CLI")
endif()
