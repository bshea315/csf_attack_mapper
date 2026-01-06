import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { playbooksApi, detectionsApi } from '../api/client';
import type { Detection, PlaybookUpdate } from '../types';

export default function PlaybookDetail() {
  const { id } = useParams<{ id: string }>();
  const playbookId = parseInt(id || '0', 10);
  const queryClient = useQueryClient();

  const [isEditing, setIsEditing] = useState(false);
  const [editForm, setEditForm] = useState<PlaybookUpdate>({});
  const [showLinkModal, setShowLinkModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');

  const { data, isLoading, error } = useQuery({
    queryKey: ['playbook', playbookId],
    queryFn: () => playbooksApi.get(playbookId),
    enabled: playbookId > 0,
  });

  // Search for detections to link
  const { data: detectionsData } = useQuery({
    queryKey: ['detections-search', searchQuery],
    queryFn: () => detectionsApi.list({ page: 1, page_size: 10, search: searchQuery || undefined }),
    enabled: showLinkModal && searchQuery.length > 0,
  });

  const updateMutation = useMutation({
    mutationFn: (update: PlaybookUpdate) => playbooksApi.update(playbookId, update),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['playbook', playbookId] });
      setIsEditing(false);
    },
  });

  const linkMutation = useMutation({
    mutationFn: (detectionId: number) => playbooksApi.linkDetection(playbookId, { detection_id: detectionId }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['playbook', playbookId] });
      setShowLinkModal(false);
      setSearchQuery('');
    },
  });

  const unlinkMutation = useMutation({
    mutationFn: (detectionId: number) => playbooksApi.unlinkDetection(playbookId, detectionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['playbook', playbookId] });
    },
  });

  const handleStartEdit = () => {
    if (data) {
      setEditForm({
        time_saved_minutes: data.playbook.time_saved_minutes,
        avg_manual_time_minutes: data.playbook.avg_manual_time_minutes || undefined,
        category: data.playbook.category || undefined,
      });
      setIsEditing(true);
    }
  };

  const handleSaveEdit = () => {
    updateMutation.mutate(editForm);
  };

  if (isLoading) {
    return (
      <div className="max-w-6xl mx-auto p-6">
        <div className="text-center py-8 text-gray-500">Loading playbook...</div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="max-w-6xl mx-auto p-6">
        <div className="bg-red-50 text-red-600 p-4 rounded">
          Error loading playbook: {(error as Error)?.message || 'Unknown error'}
        </div>
      </div>
    );
  }

  const { playbook, metrics, action_breakdown, recent_runs, linked_detections } = data;

  return (
    <div className="max-w-6xl mx-auto p-6">
      {/* Header */}
      <div className="flex justify-between items-start mb-6">
        <div>
          <Link to="/playbooks" className="text-sm text-blue-600 hover:underline mb-2 inline-block">
            &larr; Back to Playbooks
          </Link>
          <h1 className="text-2xl font-bold">{playbook.name}</h1>
          <p className="text-gray-500 text-sm">ID: {playbook.playbook_id}</p>
        </div>
        <div className="flex items-center space-x-4">
          <span
            className={`px-3 py-1 rounded-full text-sm ${
              playbook.is_active
                ? 'bg-green-100 text-green-800'
                : 'bg-gray-100 text-gray-800'
            }`}
          >
            {playbook.is_active ? 'Active' : 'Inactive'}
          </span>
          {playbook.category && (
            <span className="px-3 py-1 rounded-full text-sm bg-blue-100 text-blue-800">
              {playbook.category}
            </span>
          )}
        </div>
      </div>

      {/* Description */}
      {playbook.description && (
        <div className="bg-white rounded-lg shadow p-4 mb-6">
          <p className="text-gray-700">{playbook.description}</p>
        </div>
      )}

      {/* Key Metrics */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-2xl font-bold text-blue-600">{metrics.total_runs}</div>
          <div className="text-sm text-gray-500">Total Runs</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-2xl font-bold text-green-600">{metrics.success_rate.toFixed(1)}%</div>
          <div className="text-sm text-gray-500">Success Rate</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-2xl font-bold text-purple-600">{metrics.total_time_saved_hours.toFixed(1)}h</div>
          <div className="text-sm text-gray-500">Total Time Saved</div>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <div className="text-2xl font-bold text-orange-600">{linked_detections.length}</div>
          <div className="text-sm text-gray-500">Linked Detections</div>
        </div>
      </div>

      {/* Time Settings Section */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-semibold">Time Savings Configuration</h2>
          {!isEditing ? (
            <button
              onClick={handleStartEdit}
              className="px-4 py-2 text-sm bg-blue-600 text-white rounded hover:bg-blue-700"
            >
              Edit Settings
            </button>
          ) : (
            <div className="space-x-2">
              <button
                onClick={handleSaveEdit}
                disabled={updateMutation.isPending}
                className="px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
              >
                {updateMutation.isPending ? 'Saving...' : 'Save'}
              </button>
              <button
                onClick={() => setIsEditing(false)}
                className="px-4 py-2 text-sm bg-gray-200 rounded hover:bg-gray-300"
              >
                Cancel
              </button>
            </div>
          )}
        </div>

        {isEditing ? (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Time Saved per Run (minutes)
              </label>
              <input
                type="number"
                value={editForm.time_saved_minutes || 0}
                onChange={(e) => setEditForm({ ...editForm, time_saved_minutes: parseFloat(e.target.value) || 0 })}
                className="w-full px-3 py-2 border rounded"
                min="0"
                step="1"
              />
              <p className="text-xs text-gray-500 mt-1">
                Estimated time saved compared to manual execution
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Manual Time (minutes)
              </label>
              <input
                type="number"
                value={editForm.avg_manual_time_minutes || ''}
                onChange={(e) => setEditForm({ ...editForm, avg_manual_time_minutes: parseFloat(e.target.value) || undefined })}
                className="w-full px-3 py-2 border rounded"
                min="0"
                step="1"
                placeholder="Optional"
              />
              <p className="text-xs text-gray-500 mt-1">
                Average time if performed manually (for ROI)
              </p>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">
                Category
              </label>
              <select
                value={editForm.category || ''}
                onChange={(e) => setEditForm({ ...editForm, category: e.target.value || undefined })}
                className="w-full px-3 py-2 border rounded"
              >
                <option value="">Select category</option>
                <option value="Enrichment">Enrichment</option>
                <option value="Investigation">Investigation</option>
                <option value="Response">Response</option>
                <option value="Containment">Containment</option>
                <option value="Remediation">Remediation</option>
                <option value="Notification">Notification</option>
              </select>
            </div>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <div className="text-sm text-gray-500">Time Saved per Run</div>
              <div className="text-lg font-semibold">{playbook.time_saved_minutes} minutes</div>
            </div>
            <div>
              <div className="text-sm text-gray-500">Manual Time</div>
              <div className="text-lg font-semibold">
                {playbook.avg_manual_time_minutes ? `${playbook.avg_manual_time_minutes} minutes` : 'Not set'}
              </div>
            </div>
            <div>
              <div className="text-sm text-gray-500">Category</div>
              <div className="text-lg font-semibold">{playbook.category || 'Not set'}</div>
            </div>
          </div>
        )}
      </div>

      {/* Linked Detections Section */}
      <div className="bg-white rounded-lg shadow p-6 mb-6">
        <div className="flex justify-between items-center mb-4">
          <h2 className="text-lg font-semibold">Linked Detections</h2>
          <button
            onClick={() => setShowLinkModal(true)}
            className="px-4 py-2 text-sm bg-green-600 text-white rounded hover:bg-green-700"
          >
            + Link Detection
          </button>
        </div>

        {linked_detections.length === 0 ? (
          <p className="text-gray-500 text-center py-4">
            No detections linked yet. Link detections to track which alerts this playbook responds to.
          </p>
        ) : (
          <table className="min-w-full divide-y divide-gray-200">
            <thead>
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Detection</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Severity</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Link Type</th>
                <th className="px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {linked_detections.map((det) => (
                <tr key={det.id}>
                  <td className="px-4 py-3">
                    <Link to={`/detections/${det.id}`} className="text-blue-600 hover:underline">
                      {det.name}
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 text-xs rounded ${
                      det.severity === 'critical' ? 'bg-red-100 text-red-800' :
                      det.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                      det.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {det.severity || 'N/A'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">{det.link_type}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      onClick={() => unlinkMutation.mutate(det.id)}
                      disabled={unlinkMutation.isPending}
                      className="text-red-600 hover:text-red-800 text-sm"
                    >
                      Unlink
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Action Breakdown */}
      {action_breakdown.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6 mb-6">
          <h2 className="text-lg font-semibold mb-4">Action Breakdown</h2>
          <table className="min-w-full divide-y divide-gray-200">
            <thead>
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">App</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Runs</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Success Rate</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Avg Duration</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {action_breakdown.map((action, idx) => (
                <tr key={idx}>
                  <td className="px-4 py-3 font-medium">{action.action_name}</td>
                  <td className="px-4 py-3 text-sm text-gray-500">{action.app_name || '-'}</td>
                  <td className="px-4 py-3 text-sm">{action.total_runs}</td>
                  <td className="px-4 py-3">
                    <div className="flex items-center">
                      <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
                        <div
                          className={`h-2 rounded-full ${
                            action.success_rate >= 90 ? 'bg-green-500' :
                            action.success_rate >= 70 ? 'bg-yellow-500' :
                            'bg-red-500'
                          }`}
                          style={{ width: `${action.success_rate}%` }}
                        />
                      </div>
                      <span className="text-sm">{action.success_rate.toFixed(1)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {action.avg_duration_seconds ? `${action.avg_duration_seconds.toFixed(1)}s` : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Recent Runs */}
      {recent_runs.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold mb-4">Recent Runs</h2>
          <table className="min-w-full divide-y divide-gray-200">
            <thead>
              <tr>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Run ID</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Duration</th>
                <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {recent_runs.map((run) => (
                <tr key={run.id}>
                  <td className="px-4 py-3 font-mono text-sm">{run.playbook_run_id}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-1 text-xs rounded ${
                      run.status === 'success' ? 'bg-green-100 text-green-800' :
                      run.status === 'failure' ? 'bg-red-100 text-red-800' :
                      run.status === 'running' ? 'bg-blue-100 text-blue-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {run.status}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm">
                    {run.duration_seconds ? `${run.duration_seconds.toFixed(1)}s` : '-'}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-500">
                    {run.event_time ? new Date(run.event_time).toLocaleString() : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Link Detection Modal */}
      {showLinkModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-white rounded-lg shadow-xl p-6 w-full max-w-lg mx-4">
            <h3 className="text-lg font-semibold mb-4">Link Detection to Playbook</h3>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search detections..."
              className="w-full px-3 py-2 border rounded mb-4"
              autoFocus
            />

            {detectionsData && detectionsData.items.length > 0 ? (
              <div className="max-h-60 overflow-y-auto border rounded">
                {detectionsData.items
                  .filter((det: Detection) => !linked_detections.some(ld => ld.id === det.id))
                  .map((det: Detection) => (
                    <button
                      key={det.id}
                      onClick={() => linkMutation.mutate(det.id)}
                      disabled={linkMutation.isPending}
                      className="w-full px-4 py-2 text-left hover:bg-gray-100 flex justify-between items-center"
                    >
                      <span>{det.name}</span>
                      <span className="text-sm text-gray-500">{det.severity}</span>
                    </button>
                  ))}
              </div>
            ) : searchQuery.length > 0 ? (
              <p className="text-gray-500 text-center py-4">No detections found</p>
            ) : (
              <p className="text-gray-500 text-center py-4">Type to search for detections</p>
            )}

            <div className="mt-4 flex justify-end">
              <button
                onClick={() => {
                  setShowLinkModal(false);
                  setSearchQuery('');
                }}
                className="px-4 py-2 text-sm bg-gray-200 rounded hover:bg-gray-300"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
