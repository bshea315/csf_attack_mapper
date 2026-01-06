import { useState, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { splunkApi } from '../api/client';
import type { SplunkConfig, SplunkConfigCreate, SplunkConnectionTestResponse, ESSyncResponse, SOARSyncResponse } from '../types';

export default function Admin() {
  const queryClient = useQueryClient();
  const [showConfigForm, setShowConfigForm] = useState(false);
  const [testResult, setTestResult] = useState<SplunkConnectionTestResponse | null>(null);
  const [syncResult, setSyncResult] = useState<{
    type: 'es' | 'soar';
    result: ESSyncResponse | SOARSyncResponse;
  } | null>(null);
  const [soarDays, setSoarDays] = useState(30);

  // Form state
  const [formData, setFormData] = useState<SplunkConfigCreate>({
    name: 'default',
    base_url: '',
    auth_type: 'token',
    auth_token: '',
    auth_username: '',
    auth_password: '',
    verify_tls: true,
    es_app_namespace: 'SplunkEnterpriseSecuritySuite',
    es_owner: 'nobody',
    soar_playbook_run_index: 'phantom_playbook_run',
    soar_action_run_index: 'phantom_action_run',
    soar_time_window_days: 30,
  });

  // Load current config
  const { data: config, isLoading } = useQuery({
    queryKey: ['splunk-config'],
    queryFn: splunkApi.getConfig,
  });

  // Populate form when config loads
  useEffect(() => {
    if (config) {
      setFormData({
        name: config.name,
        base_url: config.base_url,
        auth_type: config.auth_type,
        auth_token: '',
        auth_username: config.auth_type === 'basic' ? '' : '',
        auth_password: '',
        verify_tls: config.verify_tls,
        es_app_namespace: config.es_app_namespace,
        es_owner: config.es_owner,
        soar_playbook_run_index: config.soar_playbook_run_index,
        soar_action_run_index: config.soar_action_run_index,
        soar_time_window_days: config.soar_time_window_days,
      });
    }
  }, [config]);

  // Mutations
  const createConfigMutation = useMutation({
    mutationFn: splunkApi.createConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['splunk-config'] });
      setShowConfigForm(false);
    },
  });

  const updateConfigMutation = useMutation({
    mutationFn: splunkApi.updateConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['splunk-config'] });
      setShowConfigForm(false);
    },
  });

  const deleteConfigMutation = useMutation({
    mutationFn: splunkApi.deleteConfig,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['splunk-config'] });
    },
  });

  const testConnectionMutation = useMutation({
    mutationFn: splunkApi.testConnection,
    onSuccess: (data) => setTestResult(data),
  });

  const syncESMutation = useMutation({
    mutationFn: splunkApi.syncES,
    onSuccess: (data) => setSyncResult({ type: 'es', result: data }),
  });

  const syncSOARMutation = useMutation({
    mutationFn: () => splunkApi.syncSOAR({ days: soarDays }),
    onSuccess: (data) => setSyncResult({ type: 'soar', result: data }),
  });

  const autoLinkMutation = useMutation({
    mutationFn: splunkApi.autoLinkDetections,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (config) {
      updateConfigMutation.mutate(formData);
    } else {
      createConfigMutation.mutate(formData);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-gray-500">Loading...</div>
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto p-6">
      <h1 className="text-2xl font-bold mb-6">Admin - Splunk Integration</h1>

      {/* Configuration Section */}
      <div className="bg-white rounded-lg shadow mb-6">
        <div className="p-4 border-b flex justify-between items-center">
          <h2 className="text-lg font-semibold">Splunk Configuration</h2>
          {config && !showConfigForm && (
            <div className="space-x-2">
              <button
                onClick={() => setShowConfigForm(true)}
                className="px-3 py-1 bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                Edit
              </button>
              <button
                onClick={() => {
                  if (confirm('Are you sure you want to delete this configuration?')) {
                    deleteConfigMutation.mutate();
                  }
                }}
                className="px-3 py-1 bg-red-600 text-white rounded hover:bg-red-700"
              >
                Delete
              </button>
            </div>
          )}
        </div>

        <div className="p-4">
          {!config && !showConfigForm ? (
            <div className="text-center py-8">
              <p className="text-gray-500 mb-4">No Splunk configuration found</p>
              <button
                onClick={() => setShowConfigForm(true)}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
              >
                Configure Splunk
              </button>
            </div>
          ) : showConfigForm ? (
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Base URL */}
              <div>
                <label className="block text-sm font-medium mb-1">
                  Splunk REST API URL
                </label>
                <input
                  type="text"
                  value={formData.base_url}
                  onChange={(e) => setFormData({ ...formData, base_url: e.target.value })}
                  placeholder="https://splunk-sh.company.com:8089"
                  className="w-full px-3 py-2 border rounded"
                  required
                />
                <p className="text-xs text-gray-500 mt-1">
                  Management port (usually 8089), not web port
                </p>
              </div>

              {/* Auth Type */}
              <div>
                <label className="block text-sm font-medium mb-1">
                  Authentication Type
                </label>
                <select
                  value={formData.auth_type}
                  onChange={(e) => setFormData({ ...formData, auth_type: e.target.value as 'token' | 'basic' })}
                  className="w-full px-3 py-2 border rounded"
                >
                  <option value="token">Bearer Token</option>
                  <option value="basic">Basic Auth (Username/Password)</option>
                </select>
              </div>

              {/* Auth Fields */}
              {formData.auth_type === 'token' ? (
                <div>
                  <label className="block text-sm font-medium mb-1">
                    Bearer Token
                  </label>
                  <input
                    type="password"
                    value={formData.auth_token}
                    onChange={(e) => setFormData({ ...formData, auth_token: e.target.value })}
                    placeholder={config?.has_token ? '(unchanged)' : 'Enter token'}
                    className="w-full px-3 py-2 border rounded"
                  />
                </div>
              ) : (
                <>
                  <div>
                    <label className="block text-sm font-medium mb-1">Username</label>
                    <input
                      type="text"
                      value={formData.auth_username}
                      onChange={(e) => setFormData({ ...formData, auth_username: e.target.value })}
                      className="w-full px-3 py-2 border rounded"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Password</label>
                    <input
                      type="password"
                      value={formData.auth_password}
                      onChange={(e) => setFormData({ ...formData, auth_password: e.target.value })}
                      placeholder={config?.has_password ? '(unchanged)' : 'Enter password'}
                      className="w-full px-3 py-2 border rounded"
                    />
                  </div>
                </>
              )}

              {/* TLS Verification */}
              <div className="flex items-center">
                <input
                  type="checkbox"
                  id="verify_tls"
                  checked={formData.verify_tls}
                  onChange={(e) => setFormData({ ...formData, verify_tls: e.target.checked })}
                  className="mr-2"
                />
                <label htmlFor="verify_tls" className="text-sm">
                  Verify TLS Certificate
                </label>
              </div>

              {/* ES Settings */}
              <div className="border-t pt-4 mt-4">
                <h3 className="font-medium mb-3">Enterprise Security Settings</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">ES App Namespace</label>
                    <input
                      type="text"
                      value={formData.es_app_namespace}
                      onChange={(e) => setFormData({ ...formData, es_app_namespace: e.target.value })}
                      className="w-full px-3 py-2 border rounded"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">ES Owner</label>
                    <input
                      type="text"
                      value={formData.es_owner}
                      onChange={(e) => setFormData({ ...formData, es_owner: e.target.value })}
                      className="w-full px-3 py-2 border rounded"
                    />
                  </div>
                </div>
              </div>

              {/* SOAR Settings */}
              <div className="border-t pt-4 mt-4">
                <h3 className="font-medium mb-3">SOAR Settings</h3>
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-1">Playbook Run Index</label>
                    <input
                      type="text"
                      value={formData.soar_playbook_run_index}
                      onChange={(e) => setFormData({ ...formData, soar_playbook_run_index: e.target.value })}
                      className="w-full px-3 py-2 border rounded"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1">Action Run Index</label>
                    <input
                      type="text"
                      value={formData.soar_action_run_index}
                      onChange={(e) => setFormData({ ...formData, soar_action_run_index: e.target.value })}
                      className="w-full px-3 py-2 border rounded"
                    />
                  </div>
                </div>
              </div>

              {/* Buttons */}
              <div className="flex justify-end space-x-2 pt-4">
                <button
                  type="button"
                  onClick={() => setShowConfigForm(false)}
                  className="px-4 py-2 border rounded hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={createConfigMutation.isPending || updateConfigMutation.isPending}
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
                >
                  {createConfigMutation.isPending || updateConfigMutation.isPending
                    ? 'Saving...'
                    : config ? 'Update' : 'Create'}
                </button>
              </div>
            </form>
          ) : config ? (
            <div className="space-y-4">
              <ConfigDisplay config={config} />
            </div>
          ) : null}
        </div>
      </div>

      {/* Connection Test Section */}
      {config && (
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="p-4 border-b">
            <h2 className="text-lg font-semibold">Connection Test</h2>
          </div>
          <div className="p-4">
            <button
              onClick={() => testConnectionMutation.mutate()}
              disabled={testConnectionMutation.isPending}
              className="px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
            >
              {testConnectionMutation.isPending ? 'Testing...' : 'Test Connection'}
            </button>

            {testResult && (
              <div className={`mt-4 p-4 rounded ${testResult.success ? 'bg-green-50' : 'bg-red-50'}`}>
                <p className={`font-medium ${testResult.success ? 'text-green-800' : 'text-red-800'}`}>
                  {testResult.message}
                </p>
                {testResult.server_info && (
                  <div className="mt-2 text-sm text-gray-600">
                    <p>Version: {testResult.server_info.version}</p>
                    <p>Server: {testResult.server_info.server_name}</p>
                    <p>OS: {testResult.server_info.os_name}</p>
                    <p>License: {testResult.server_info.license_state}</p>
                  </div>
                )}
                {testResult.error && (
                  <p className="mt-2 text-sm text-red-600">{testResult.error}</p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Sync Operations Section */}
      {config && (
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="p-4 border-b">
            <h2 className="text-lg font-semibold">Sync Operations</h2>
          </div>
          <div className="p-4 space-y-6">
            {/* ES Sync */}
            <div>
              <h3 className="font-medium mb-2">ES Correlation Searches</h3>
              <p className="text-sm text-gray-600 mb-2">
                Import all ES correlation searches as detections.
                {config.last_es_sync_at && (
                  <span className="ml-1">
                    Last sync: {new Date(config.last_es_sync_at).toLocaleString()}
                  </span>
                )}
              </p>
              <button
                onClick={() => syncESMutation.mutate()}
                disabled={syncESMutation.isPending}
                className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
              >
                {syncESMutation.isPending ? 'Syncing...' : 'Sync ES Detections'}
              </button>
            </div>

            {/* SOAR Sync */}
            <div className="border-t pt-4">
              <h3 className="font-medium mb-2">SOAR Execution Logs</h3>
              <p className="text-sm text-gray-600 mb-2">
                Import playbook and action execution history.
                {config.last_soar_sync_at && (
                  <span className="ml-1">
                    Last sync: {new Date(config.last_soar_sync_at).toLocaleString()}
                  </span>
                )}
              </p>
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <label className="text-sm">Days to sync:</label>
                  <input
                    type="number"
                    value={soarDays}
                    onChange={(e) => setSoarDays(parseInt(e.target.value) || 30)}
                    min={1}
                    max={365}
                    className="w-20 px-2 py-1 border rounded"
                  />
                </div>
                <button
                  onClick={() => syncSOARMutation.mutate()}
                  disabled={syncSOARMutation.isPending}
                  className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
                >
                  {syncSOARMutation.isPending ? 'Syncing...' : 'Sync SOAR Logs'}
                </button>
              </div>
            </div>

            {/* Auto-Link */}
            <div className="border-t pt-4">
              <h3 className="font-medium mb-2">Auto-Link Detections</h3>
              <p className="text-sm text-gray-600 mb-2">
                Automatically link detections to playbooks based on name matching and keywords.
              </p>
              <button
                onClick={() => autoLinkMutation.mutate()}
                disabled={autoLinkMutation.isPending}
                className="px-4 py-2 bg-purple-600 text-white rounded hover:bg-purple-700 disabled:opacity-50"
              >
                {autoLinkMutation.isPending ? 'Linking...' : 'Auto-Link Detections'}
              </button>
              {autoLinkMutation.isSuccess && (
                <p className="mt-2 text-sm text-green-600">
                  Created {autoLinkMutation.data.links_created} new links
                </p>
              )}
            </div>

            {/* Sync Results */}
            {syncResult && (
              <div className="border-t pt-4">
                <h3 className="font-medium mb-2">
                  {syncResult.type === 'es' ? 'ES Sync' : 'SOAR Sync'} Results
                </h3>
                <div className={`p-4 rounded ${syncResult.result.success ? 'bg-green-50' : 'bg-red-50'}`}>
                  {syncResult.type === 'es' ? (
                    <ESSyncResultDisplay result={syncResult.result as ESSyncResponse} />
                  ) : (
                    <SOARSyncResultDisplay result={syncResult.result as SOARSyncResponse} />
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// Helper components
function ConfigDisplay({ config }: { config: SplunkConfig }) {
  return (
    <div className="grid grid-cols-2 gap-4 text-sm">
      <div>
        <span className="text-gray-500">Name:</span>
        <span className="ml-2 font-medium">{config.name}</span>
      </div>
      <div>
        <span className="text-gray-500">URL:</span>
        <span className="ml-2 font-medium">{config.base_url}</span>
      </div>
      <div>
        <span className="text-gray-500">Auth Type:</span>
        <span className="ml-2 font-medium">{config.auth_type}</span>
      </div>
      <div>
        <span className="text-gray-500">TLS Verification:</span>
        <span className="ml-2 font-medium">{config.verify_tls ? 'Enabled' : 'Disabled'}</span>
      </div>
      <div>
        <span className="text-gray-500">ES Namespace:</span>
        <span className="ml-2 font-medium">{config.es_app_namespace}</span>
      </div>
      <div>
        <span className="text-gray-500">Playbook Index:</span>
        <span className="ml-2 font-medium">{config.soar_playbook_run_index}</span>
      </div>
      <div>
        <span className="text-gray-500">Last ES Sync:</span>
        <span className="ml-2 font-medium">
          {config.last_es_sync_at ? new Date(config.last_es_sync_at).toLocaleString() : 'Never'}
        </span>
      </div>
      <div>
        <span className="text-gray-500">Last SOAR Sync:</span>
        <span className="ml-2 font-medium">
          {config.last_soar_sync_at ? new Date(config.last_soar_sync_at).toLocaleString() : 'Never'}
        </span>
      </div>
    </div>
  );
}

function ESSyncResultDisplay({ result }: { result: ESSyncResponse }) {
  return (
    <div className="space-y-2">
      <p><span className="font-medium">Status:</span> {result.success ? 'Success' : 'Failed'}</p>
      <p><span className="font-medium">Total Found:</span> {result.total_found}</p>
      <p><span className="font-medium">Created:</span> {result.created}</p>
      <p><span className="font-medium">Updated:</span> {result.updated}</p>
      <p><span className="font-medium">Unchanged:</span> {result.unchanged}</p>
      <p><span className="font-medium">Failed:</span> {result.failed}</p>
      <p><span className="font-medium">Duration:</span> {result.duration_seconds.toFixed(2)}s</p>
      {result.errors.length > 0 && (
        <div className="mt-2">
          <p className="font-medium text-red-600">Errors:</p>
          <ul className="list-disc list-inside text-sm text-red-600">
            {result.errors.map((err, i) => (
              <li key={i}>{err}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function SOARSyncResultDisplay({ result }: { result: SOARSyncResponse }) {
  return (
    <div className="space-y-2">
      <p><span className="font-medium">Status:</span> {result.success ? 'Success' : 'Failed'}</p>
      <p><span className="font-medium">Playbook Runs Found:</span> {result.playbook_runs_found}</p>
      <p><span className="font-medium">Playbook Runs Created:</span> {result.playbook_runs_created}</p>
      <p><span className="font-medium">Action Runs Found:</span> {result.action_runs_found}</p>
      <p><span className="font-medium">Action Runs Created:</span> {result.action_runs_created}</p>
      <p><span className="font-medium">Playbooks Discovered:</span> {result.playbooks_discovered}</p>
      <p><span className="font-medium">Duration:</span> {result.duration_seconds.toFixed(2)}s</p>
      {result.errors.length > 0 && (
        <div className="mt-2">
          <p className="font-medium text-red-600">Errors:</p>
          <ul className="list-disc list-inside text-sm text-red-600">
            {result.errors.map((err, i) => (
              <li key={i}>{err}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
