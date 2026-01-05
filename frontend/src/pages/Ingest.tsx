import { useState, useCallback } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ingestApi } from '../api/client';
import { Upload, FileText, FileCode, ClipboardPaste, CheckCircle, XCircle, Loader } from 'lucide-react';
import clsx from 'clsx';

type TabType = 'csv' | 'yaml' | 'paste';

export default function Ingest() {
  const [activeTab, setActiveTab] = useState<TabType>('csv');
  const [file, setFile] = useState<File | null>(null);
  const [pasteContent, setPasteContent] = useState('');
  const [dragActive, setDragActive] = useState(false);
  const queryClient = useQueryClient();

  // Fetch ingest history
  const { data: batches } = useQuery({
    queryKey: ['ingest-batches'],
    queryFn: ingestApi.getBatches,
  });

  // Mutations for each ingest type
  const csvMutation = useMutation({
    mutationFn: ingestApi.uploadCsv,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ingest-batches'] });
      queryClient.invalidateQueries({ queryKey: ['detections'] });
      queryClient.invalidateQueries({ queryKey: ['overview'] });
      setFile(null);
    },
  });

  const yamlMutation = useMutation({
    mutationFn: ingestApi.uploadYaml,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ingest-batches'] });
      queryClient.invalidateQueries({ queryKey: ['detections'] });
      queryClient.invalidateQueries({ queryKey: ['overview'] });
      setFile(null);
    },
  });

  const pasteMutation = useMutation({
    mutationFn: ingestApi.paste,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['ingest-batches'] });
      queryClient.invalidateQueries({ queryKey: ['detections'] });
      queryClient.invalidateQueries({ queryKey: ['overview'] });
      setPasteContent('');
    },
  });

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);

    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
    }
  }, []);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleSubmit = async () => {
    if (activeTab === 'csv' && file) {
      csvMutation.mutate(file);
    } else if (activeTab === 'yaml' && file) {
      yamlMutation.mutate(file);
    } else if (activeTab === 'paste' && pasteContent.trim()) {
      pasteMutation.mutate(pasteContent);
    }
  };

  const isLoading = csvMutation.isPending || yamlMutation.isPending || pasteMutation.isPending;
  const currentMutation = activeTab === 'csv' ? csvMutation : activeTab === 'yaml' ? yamlMutation : pasteMutation;

  const tabs = [
    { id: 'csv' as TabType, label: 'CSV Upload', icon: FileText },
    { id: 'yaml' as TabType, label: 'YAML Upload', icon: FileCode },
    { id: 'paste' as TabType, label: 'Paste', icon: ClipboardPaste },
  ];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Import Detections</h1>
        <p className="text-gray-600">
          Upload CSV, YAML, or paste detection content directly
        </p>
      </div>

      {/* Tabs */}
      <div className="bg-white rounded-lg shadow">
        <div className="border-b border-gray-200">
          <nav className="flex -mb-px">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => {
                  setActiveTab(tab.id);
                  setFile(null);
                }}
                className={clsx(
                  'flex items-center gap-2 px-6 py-4 border-b-2 text-sm font-medium',
                  activeTab === tab.id
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                )}
              >
                <tab.icon className="h-5 w-5" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        <div className="p-6">
          {/* CSV Upload */}
          {activeTab === 'csv' && (
            <div>
              <p className="text-sm text-gray-600 mb-4">
                Upload a CSV file with columns: <code className="bg-gray-100 px-1 rounded">detection_id</code>,{' '}
                <code className="bg-gray-100 px-1 rounded">name</code>,{' '}
                <code className="bg-gray-100 px-1 rounded">spl</code>,{' '}
                <code className="bg-gray-100 px-1 rounded">severity</code> (optional),{' '}
                <code className="bg-gray-100 px-1 rounded">status</code> (optional),{' '}
                <code className="bg-gray-100 px-1 rounded">mitre_tags</code> (optional).
              </p>
              <div
                className={clsx(
                  'border-2 border-dashed rounded-lg p-8 text-center transition-colors',
                  dragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-gray-400',
                  file && 'border-green-500 bg-green-50'
                )}
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
              >
                <input
                  type="file"
                  accept=".csv"
                  onChange={handleFileChange}
                  className="hidden"
                  id="csv-upload"
                />
                {file ? (
                  <div className="flex items-center justify-center gap-3">
                    <CheckCircle className="h-8 w-8 text-green-500" />
                    <div>
                      <p className="font-medium text-gray-900">{file.name}</p>
                      <p className="text-sm text-gray-500">
                        {(file.size / 1024).toFixed(1)} KB
                      </p>
                    </div>
                    <button
                      onClick={() => setFile(null)}
                      className="ml-4 text-sm text-red-600 hover:text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                ) : (
                  <label htmlFor="csv-upload" className="cursor-pointer">
                    <Upload className="h-10 w-10 mx-auto text-gray-400" />
                    <p className="mt-2 text-gray-600">
                      Drag and drop a CSV file, or{' '}
                      <span className="text-blue-600 hover:text-blue-700">
                        click to browse
                      </span>
                    </p>
                  </label>
                )}
              </div>
            </div>
          )}

          {/* YAML Upload */}
          {activeTab === 'yaml' && (
            <div>
              <p className="text-sm text-gray-600 mb-4">
                Upload a YAML file with Splunk detection definitions. Supports Splunk Enterprise Security
                content format with <code className="bg-gray-100 px-1 rounded">search</code> field.
              </p>
              <div
                className={clsx(
                  'border-2 border-dashed rounded-lg p-8 text-center transition-colors',
                  dragActive ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-gray-400',
                  file && 'border-green-500 bg-green-50'
                )}
                onDragEnter={handleDrag}
                onDragLeave={handleDrag}
                onDragOver={handleDrag}
                onDrop={handleDrop}
              >
                <input
                  type="file"
                  accept=".yml,.yaml"
                  onChange={handleFileChange}
                  className="hidden"
                  id="yaml-upload"
                />
                {file ? (
                  <div className="flex items-center justify-center gap-3">
                    <CheckCircle className="h-8 w-8 text-green-500" />
                    <div>
                      <p className="font-medium text-gray-900">{file.name}</p>
                      <p className="text-sm text-gray-500">
                        {(file.size / 1024).toFixed(1)} KB
                      </p>
                    </div>
                    <button
                      onClick={() => setFile(null)}
                      className="ml-4 text-sm text-red-600 hover:text-red-700"
                    >
                      Remove
                    </button>
                  </div>
                ) : (
                  <label htmlFor="yaml-upload" className="cursor-pointer">
                    <Upload className="h-10 w-10 mx-auto text-gray-400" />
                    <p className="mt-2 text-gray-600">
                      Drag and drop a YAML file, or{' '}
                      <span className="text-blue-600 hover:text-blue-700">
                        click to browse
                      </span>
                    </p>
                  </label>
                )}
              </div>
            </div>
          )}

          {/* Paste */}
          {activeTab === 'paste' && (
            <div>
              <p className="text-sm text-gray-600 mb-4">
                Paste detection content in delimiter format. Each detection should have:{' '}
                <code className="bg-gray-100 px-1 rounded">detection_id|||name|||spl|||severity|||status</code>.
                Separate multiple detections with a newline.
              </p>
              <textarea
                value={pasteContent}
                onChange={(e) => setPasteContent(e.target.value)}
                placeholder="detection_id|||Detection Name|||index=main | stats count|||high|||enabled"
                className="w-full h-64 p-4 border border-gray-300 rounded-lg font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
              <p className="mt-2 text-sm text-gray-500">
                {pasteContent.split('\n').filter((l) => l.trim()).length} lines detected
              </p>
            </div>
          )}

          {/* Error Display */}
          {currentMutation.isError && (
            <div className="mt-4 p-4 bg-red-50 border border-red-200 rounded-lg flex items-start gap-3">
              <XCircle className="h-5 w-5 text-red-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-red-800">Import Failed</p>
                <p className="text-sm text-red-600">
                  {(currentMutation.error as Error)?.message || 'An error occurred during import.'}
                </p>
              </div>
            </div>
          )}

          {/* Success Display */}
          {currentMutation.isSuccess && (
            <div className="mt-4 p-4 bg-green-50 border border-green-200 rounded-lg flex items-start gap-3">
              <CheckCircle className="h-5 w-5 text-green-500 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-green-800">Import Successful</p>
                <p className="text-sm text-green-600">
                  Detections have been imported and processed.
                </p>
              </div>
            </div>
          )}

          {/* Submit Button */}
          <div className="mt-6 flex justify-end">
            <button
              onClick={handleSubmit}
              disabled={
                isLoading ||
                (activeTab !== 'paste' && !file) ||
                (activeTab === 'paste' && !pasteContent.trim())
              }
              className={clsx(
                'flex items-center gap-2 px-6 py-2 rounded-lg font-medium',
                'bg-blue-600 text-white hover:bg-blue-700',
                'disabled:opacity-50 disabled:cursor-not-allowed'
              )}
            >
              {isLoading ? (
                <>
                  <Loader className="h-5 w-5 animate-spin" />
                  Processing...
                </>
              ) : (
                <>
                  <Upload className="h-5 w-5" />
                  Import Detections
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Import History */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Import History</h2>
        </div>
        <div className="divide-y divide-gray-200">
          {batches && batches.length > 0 ? (
            batches.slice(0, 10).map((batch) => (
              <div key={batch.id} className="px-6 py-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {batch.status === 'completed' ? (
                      <CheckCircle className="h-5 w-5 text-green-500" />
                    ) : batch.status === 'failed' ? (
                      <XCircle className="h-5 w-5 text-red-500" />
                    ) : (
                      <Loader className="h-5 w-5 text-blue-500 animate-spin" />
                    )}
                    <div>
                      <p className="font-medium text-gray-900">
                        {batch.source_filename || `${batch.source_type.toUpperCase()} Import`}
                      </p>
                      <p className="text-sm text-gray-500">
                        {new Date(batch.created_at).toLocaleString()}
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <p className="text-sm">
                      <span className="text-green-600">{batch.successful}</span> /
                      <span className="text-gray-600"> {batch.total_records}</span> records
                    </p>
                    {batch.failed > 0 && (
                      <p className="text-sm text-red-600">{batch.failed} failed</p>
                    )}
                  </div>
                </div>
              </div>
            ))
          ) : (
            <div className="px-6 py-8 text-center text-gray-500">
              <FileText className="h-12 w-12 mx-auto mb-2 text-gray-400" />
              <p>No import history yet.</p>
            </div>
          )}
        </div>
      </div>

      {/* Format Examples */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">Format Examples</h2>
        <div className="space-y-4">
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-2">CSV Format</h3>
            <pre className="bg-gray-50 p-3 rounded text-xs overflow-x-auto">
{`detection_id,name,spl,severity,status,mitre_tags
DET-001,Brute Force Login,index=auth | stats count by user | where count > 10,high,enabled,"T1110,T1078"
DET-002,Suspicious Process,index=endpoint process_name=powershell.exe,medium,enabled,T1059.001`}
            </pre>
          </div>
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-2">YAML Format</h3>
            <pre className="bg-gray-50 p-3 rounded text-xs overflow-x-auto">
{`detections:
  - detection_id: DET-001
    name: Brute Force Login Detection
    search: |
      index=auth
      | stats count by user
      | where count > 10
    severity: high
    status: enabled
    mitre_tags:
      - T1110
      - T1078`}
            </pre>
          </div>
          <div>
            <h3 className="text-sm font-medium text-gray-700 mb-2">Paste Format</h3>
            <pre className="bg-gray-50 p-3 rounded text-xs overflow-x-auto">
{`DET-001|||Brute Force Login|||index=auth | stats count by user | where count > 10|||high|||enabled
DET-002|||Suspicious Process|||index=endpoint process_name=powershell.exe|||medium|||enabled`}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
