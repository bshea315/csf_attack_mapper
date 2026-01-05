import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { detectionsApi } from '../api/client';
import { ArrowLeft, Copy, Check, CheckCircle, XCircle } from 'lucide-react';
import { useState } from 'react';
import clsx from 'clsx';

export default function DetectionDetail() {
  const { id } = useParams<{ id: string }>();
  const [copied, setCopied] = useState(false);

  const { data: detection, isLoading } = useQuery({
    queryKey: ['detection', id],
    queryFn: () => detectionsApi.get(Number(id)),
    enabled: !!id,
  });

  const copyToClipboard = async () => {
    if (detection?.spl) {
      await navigator.clipboard.writeText(detection.spl);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  if (!detection) {
    return <div>Detection not found</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link
          to="/detections"
          className="p-2 hover:bg-gray-100 rounded-lg"
        >
          <ArrowLeft className="h-5 w-5" />
        </Link>
        <div>
          <h1 className="text-2xl font-bold text-gray-900">{detection.name}</h1>
          <p className="text-gray-500">{detection.detection_id}</p>
        </div>
      </div>

      {/* Status badges */}
      <div className="flex gap-2">
        {detection.severity && (
          <span className={clsx(
            'px-3 py-1 text-sm font-medium rounded-full',
            detection.severity === 'critical' ? 'bg-red-100 text-red-800' :
            detection.severity === 'high' ? 'bg-orange-100 text-orange-800' :
            detection.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
            'bg-green-100 text-green-800'
          )}>
            {detection.severity}
          </span>
        )}
        <span className={clsx(
          'px-3 py-1 text-sm font-medium rounded-full',
          detection.status === 'enabled' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
        )}>
          {detection.status}
        </span>
      </div>

      {/* Description */}
      {detection.description && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-2">Description</h2>
          <p className="text-gray-700">{detection.description}</p>
        </div>
      )}

      {/* SPL Query */}
      <div className="bg-white rounded-lg shadow p-6">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-lg font-semibold text-gray-900">SPL Query</h2>
          <button
            onClick={copyToClipboard}
            className="flex items-center gap-2 px-3 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded"
          >
            {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
            {copied ? 'Copied!' : 'Copy'}
          </button>
        </div>
        <pre className="spl-code whitespace-pre-wrap">{detection.spl}</pre>
      </div>

      {/* SPL Artifacts */}
      {detection.spl_artifacts && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Parsed Artifacts</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {detection.spl_artifacts.indexes.length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-gray-500 mb-1">Indexes</h3>
                <div className="flex flex-wrap gap-1">
                  {detection.spl_artifacts.indexes.map((idx) => (
                    <span key={idx} className="px-2 py-1 text-xs bg-blue-100 text-blue-800 rounded">
                      {idx}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {detection.spl_artifacts.sourcetypes.length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-gray-500 mb-1">Sourcetypes</h3>
                <div className="flex flex-wrap gap-1">
                  {detection.spl_artifacts.sourcetypes.map((st) => (
                    <span key={st} className="px-2 py-1 text-xs bg-purple-100 text-purple-800 rounded">
                      {st}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {detection.spl_artifacts.commands_used.length > 0 && (
              <div>
                <h3 className="text-sm font-medium text-gray-500 mb-1">Commands</h3>
                <div className="flex flex-wrap gap-1">
                  {detection.spl_artifacts.commands_used.map((cmd) => (
                    <span key={cmd} className="px-2 py-1 text-xs bg-gray-100 text-gray-800 rounded">
                      {cmd}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {detection.spl_artifacts.complexity_score !== null && (
              <div>
                <h3 className="text-sm font-medium text-gray-500 mb-1">Complexity Score</h3>
                <span className={clsx(
                  'px-2 py-1 text-xs rounded',
                  detection.spl_artifacts.complexity_score > 60 ? 'bg-red-100 text-red-800' :
                  detection.spl_artifacts.complexity_score > 30 ? 'bg-yellow-100 text-yellow-800' :
                  'bg-green-100 text-green-800'
                )}>
                  {detection.spl_artifacts.complexity_score}/100
                </span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* MITRE Mappings */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">MITRE ATT&CK Mappings</h2>
        {detection.mitre_mappings.length === 0 ? (
          <p className="text-gray-500">No MITRE mappings found.</p>
        ) : (
          <div className="space-y-3">
            {detection.mitre_mappings.map((mapping) => (
              <div
                key={mapping.technique_id}
                className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
              >
                <div className="flex items-center gap-3">
                  {mapping.is_accepted ? (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  ) : (
                    <XCircle className="h-5 w-5 text-red-500" />
                  )}
                  <div>
                    <p className="font-medium text-gray-900">
                      {mapping.technique_id}: {mapping.technique_name}
                    </p>
                    <p className="text-sm text-gray-500">
                      Method: {mapping.method} | Confidence: {(mapping.confidence * 100).toFixed(0)}%
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* CSF Impacts */}
      <div className="bg-white rounded-lg shadow p-6">
        <h2 className="text-lg font-semibold text-gray-900 mb-4">CSF 2.0 Impact</h2>
        {detection.csf_impacts.length === 0 ? (
          <p className="text-gray-500">No CSF impacts computed.</p>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {detection.csf_impacts.map((impact) => (
              <div
                key={impact.csf_id}
                className="p-3 bg-gray-50 rounded-lg"
              >
                <div className="flex items-center justify-between">
                  <span className={clsx(
                    'px-2 py-1 text-xs font-medium rounded',
                    impact.function === 'GOVERN' ? 'bg-csf-govern text-white' :
                    impact.function === 'IDENTIFY' ? 'bg-csf-identify text-white' :
                    impact.function === 'PROTECT' ? 'bg-csf-protect text-white' :
                    impact.function === 'DETECT' ? 'bg-csf-detect text-white' :
                    impact.function === 'RESPOND' ? 'bg-csf-respond text-white' :
                    'bg-csf-recover text-white'
                  )}>
                    {impact.function}
                  </span>
                  <span className="text-sm font-medium">
                    {(impact.impact_score * 100).toFixed(0)}%
                  </span>
                </div>
                <p className="mt-2 text-sm text-gray-600">{impact.csf_id}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
