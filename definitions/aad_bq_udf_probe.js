/**
 * BigQuery UDF Sandbox Probe
 *
 * Tests whether BigQuery JavaScript UDFs provide a different/weaker sandbox
 * that could be exploited for cross-tenant attacks.
 *
 * BigQuery UDFs run in a separate JavaScript sandbox at query time,
 * which may have different restrictions than compilation-time.
 */

const probeId = `UDF_PROBE_${Date.now()}`;

dataform.projectConfig.defaultDatabase = "shir-research-3";
dataform.projectConfig.defaultSchema = "dataform_poc";

// Create a UDF that probes the BigQuery JavaScript sandbox
operate("create_probe_udf").queries([
  `-- Create a UDF to probe the BigQuery sandbox
   CREATE OR REPLACE FUNCTION \`shir-research-3.dataform_poc.probe_udf\`(x INT64)
   RETURNS STRING
   LANGUAGE js AS r'''
   var results = {
     probe_id: "${probeId}",
     probe_time: new Date().toISOString(),
     tests: {}
   };

   // Test 1: Check global objects
   try {
     results.tests.globals = {
       hasGlobalThis: typeof globalThis !== "undefined",
       hasGlobal: typeof global !== "undefined",
       hasSelf: typeof self !== "undefined",
       hasWindow: typeof window !== "undefined",
       hasProcess: typeof process !== "undefined",
       hasConsole: typeof console !== "undefined"
     };
   } catch (e) {
     results.tests.globals = {error: e.message};
   }

   // Test 2: Check what functions are available
   try {
     results.tests.functions = {
       hasEval: typeof eval !== "undefined",
       hasFunction: typeof Function !== "undefined",
       hasSetTimeout: typeof setTimeout !== "undefined",
       hasSetInterval: typeof setInterval !== "undefined",
       hasFetch: typeof fetch !== "undefined",
       hasXMLHttpRequest: typeof XMLHttpRequest !== "undefined"
     };
   } catch (e) {
     results.tests.functions = {error: e.message};
   }

   // Test 3: Try eval
   try {
     var evalResult = eval("1 + 1");
     results.tests.eval = {works: evalResult === 2, result: evalResult};
   } catch (e) {
     results.tests.eval = {works: false, error: e.message};
   }

   // Test 4: Try Function constructor
   try {
     var fn = new Function("return 2 + 2");
     var fnResult = fn();
     results.tests.functionConstructor = {works: fnResult === 4, result: fnResult};
   } catch (e) {
     results.tests.functionConstructor = {works: false, error: e.message};
   }

   // Test 5: Check for SharedArrayBuffer
   try {
     results.tests.sharedMemory = {
       hasSharedArrayBuffer: typeof SharedArrayBuffer !== "undefined",
       hasAtomics: typeof Atomics !== "undefined"
     };
   } catch (e) {
     results.tests.sharedMemory = {error: e.message};
   }

   // Test 6: Try to access prototype
   try {
     var prototypeTest = Object.prototype.__udfCanary;
     Object.prototype.__udfCanary = "${probeId}";
     results.tests.prototype = {
       canModify: true,
       previousValue: prototypeTest
     };
   } catch (e) {
     results.tests.prototype = {canModify: false, error: e.message};
   }

   return JSON.stringify(results);
   ''';`
]);

// Create operation that calls the UDF and stores results
operate("run_udf_probe").queries([
  `-- Run the UDF probe and store results
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.udf_probe_results\` AS
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     \`shir-research-3.dataform_poc.probe_udf\`(1) as udf_results`
]).dependencies(["create_probe_udf"]);

// Create a second UDF call to check for state persistence
operate("run_udf_persistence_check").queries([
  `-- Check if state persists across UDF calls
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.udf_persistence_results\` AS
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as check_time,
     \`shir-research-3.dataform_poc.probe_udf\`(2) as second_call_results`
]).dependencies(["run_udf_probe"]);

publish("udf_probe_view").query(`
  SELECT
    '${probeId}' as probe_id,
    CURRENT_TIMESTAMP() as view_created
`);
