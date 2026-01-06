import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { analyticsApi, ingestApi } from '../api/client';
import { Link } from 'react-router-dom';
import {
  FileSearch,
  Target,
  Shield,
  AlertTriangle,
  TrendingUp,
  CheckCircle,
  RefreshCw,
  X,
} from 'lucide-react';

function StatCard({
  title,
  value,
  subtitle,
  icon: Icon,
  color,
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  icon: React.ElementType;
  color: string;
}) {
  return (
    <div className="bg-white rounded-lg shadow p-4 sm:p-6">
      <div className="flex items-center">
        <div className={`p-2 sm:p-3 rounded-lg ${color}`}>
          <Icon className="h-5 w-5 sm:h-6 sm:w-6 text-white" />
        </div>
        <div className="ml-3 sm:ml-4 min-w-0">
          <p className="text-xs sm:text-sm font-medium text-gray-500 truncate">{title}</p>
          <p className="text-xl sm:text-2xl font-semibold text-gray-900">{value}</p>
          {subtitle && <p className="text-xs sm:text-sm text-gray-500 truncate">{subtitle}</p>}
        </div>
      </div>
    </div>
  );
}

// Confirmation Modal Component
function ReprocessModal({
  isOpen,
  onClose,
  onConfirm,
  isLoading,
  result,
}: {
  isOpen: boolean;
  onClose: () => void;
  onConfirm: () => void;
  isLoading: boolean;
  result: { total_detections: number; successful: number; failed: number; mapper_type: string } | null;
}) {
  const [confirmText, setConfirmText] = useState('');

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto">
      <div className="flex min-h-full items-center justify-center p-4">
        {/* Backdrop */}
        <div className="fixed inset-0 bg-black bg-opacity-50 transition-opacity" onClick={onClose} />

        {/* Modal */}
        <div className="relative bg-white rounded-lg shadow-xl max-w-md w-full p-6">
          <button
            onClick={onClose}
            className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
          >
            <X className="h-5 w-5" />
          </button>

          {result ? (
            // Show results
            <div>
              <div className="flex items-center mb-4">
                <CheckCircle className="h-8 w-8 text-green-500 mr-3" />
                <h3 className="text-lg font-semibold text-gray-900">Reprocessing Complete</h3>
              </div>
              <div className="bg-gray-50 rounded-lg p-4 space-y-2">
                <p className="text-sm text-gray-600">
                  <span className="font-medium">Mapper:</span> {result.mapper_type}
                </p>
                <p className="text-sm text-gray-600">
                  <span className="font-medium">Total Detections:</span> {result.total_detections}
                </p>
                <p className="text-sm text-green-600">
                  <span className="font-medium">Successful:</span> {result.successful}
                </p>
                {result.failed > 0 && (
                  <p className="text-sm text-red-600">
                    <span className="font-medium">Failed:</span> {result.failed}
                  </p>
                )}
              </div>
              <button
                onClick={onClose}
                className="mt-4 w-full px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Close
              </button>
            </div>
          ) : (
            // Show confirmation form
            <div>
              <div className="flex items-center mb-4">
                <RefreshCw className="h-8 w-8 text-orange-500 mr-3" />
                <h3 className="text-lg font-semibold text-gray-900">Reprocess All Mappings</h3>
              </div>

              <div className="bg-orange-50 border border-orange-200 rounded-lg p-4 mb-4">
                <p className="text-sm text-orange-800 font-medium mb-2">Warning: This action will:</p>
                <ul className="text-sm text-orange-700 list-disc list-inside space-y-1">
                  <li>Clear ALL existing MITRE technique mappings</li>
                  <li>Clear ALL CSF impact calculations</li>
                  <li>Re-run the enhanced mapper on all detections</li>
                  <li>This cannot be undone</li>
                </ul>
              </div>

              <p className="text-sm text-gray-600 mb-2">
                Type <span className="font-mono font-bold bg-gray-100 px-1">REPROCESS</span> to confirm:
              </p>
              <input
                type="text"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                placeholder="Type REPROCESS"
                disabled={isLoading}
              />

              <div className="flex gap-3 mt-4">
                <button
                  onClick={onClose}
                  className="flex-1 px-4 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50"
                  disabled={isLoading}
                >
                  Cancel
                </button>
                <button
                  onClick={onConfirm}
                  disabled={confirmText !== 'REPROCESS' || isLoading}
                  className="flex-1 px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center"
                >
                  {isLoading ? (
                    <>
                      <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                      Processing...
                    </>
                  ) : (
                    'Reprocess All'
                  )}
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [showReprocessModal, setShowReprocessModal] = useState(false);
  const [reprocessResult, setReprocessResult] = useState<{
    total_detections: number;
    successful: number;
    failed: number;
    mapper_type: string;
  } | null>(null);

  const queryClient = useQueryClient();

  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['overview'],
    queryFn: analyticsApi.getOverview,
  });

  const { data: gaps } = useQuery({
    queryKey: ['gaps'],
    queryFn: analyticsApi.getGaps,
  });

  const { data: csf } = useQuery({
    queryKey: ['csf-coverage'],
    queryFn: analyticsApi.getCsfCoverage,
  });

  const reprocessMutation = useMutation({
    mutationFn: () => ingestApi.reprocessMappings({
      use_enhanced_mapper: true,
      confirmation: 'REPROCESS',
    }),
    onSuccess: (data) => {
      setReprocessResult(data);
      // Invalidate all queries to refresh data
      queryClient.invalidateQueries();
    },
  });

  const handleReprocess = () => {
    reprocessMutation.mutate();
  };

  const handleCloseModal = () => {
    setShowReprocessModal(false);
    setReprocessResult(null);
  };

  if (overviewLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  return (
    <div className="space-y-4 sm:space-y-6">
      <div>
        <h1 className="text-xl sm:text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-sm sm:text-base text-gray-600">Detection coverage overview and key metrics</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 sm:gap-4">
        <StatCard
          title="Total Detections"
          value={overview?.total_detections || 0}
          subtitle={`${overview?.enabled_percentage?.toFixed(0)}% enabled`}
          icon={FileSearch}
          color="bg-blue-500"
        />
        <StatCard
          title="ATT&CK Coverage"
          value={`${overview?.technique_coverage_percentage?.toFixed(0)}%`}
          subtitle={`${overview?.techniques_covered} of ${overview?.total_techniques} techniques`}
          icon={Target}
          color="bg-purple-500"
        />
        <StatCard
          title="CSF Score"
          value={`${((csf?.overall_score || 0) * 100).toFixed(0)}%`}
          subtitle="Overall coverage"
          icon={Shield}
          color="bg-green-500"
        />
        <StatCard
          title="Gaps Identified"
          value={gaps?.total_gaps || 0}
          subtitle={`${gaps?.critical_gaps || 0} critical`}
          icon={AlertTriangle}
          color="bg-orange-500"
        />
      </div>

      {/* CSF Function Scores */}
      {csf && (
        <div className="bg-white rounded-lg shadow p-4 sm:p-6">
          <h2 className="text-base sm:text-lg font-semibold text-gray-900 mb-3 sm:mb-4">CSF 2.0 Function Coverage</h2>
          <div className="grid grid-cols-3 sm:grid-cols-6 gap-2 sm:gap-4">
            {[
              { name: 'Govern', score: csf.govern_score, color: 'bg-csf-govern' },
              { name: 'Identify', score: csf.identify_score, color: 'bg-csf-identify' },
              { name: 'Protect', score: csf.protect_score, color: 'bg-csf-protect' },
              { name: 'Detect', score: csf.detect_score, color: 'bg-csf-detect' },
              { name: 'Respond', score: csf.respond_score, color: 'bg-csf-respond' },
              { name: 'Recover', score: csf.recover_score, color: 'bg-csf-recover' },
            ].map((func) => (
              <div key={func.name} className="text-center">
                <div
                  className={`mx-auto w-12 h-12 sm:w-16 sm:h-16 rounded-full ${func.color} flex items-center justify-center mb-1 sm:mb-2`}
                >
                  <span className="text-white text-xs sm:text-base font-bold">
                    {(func.score * 100).toFixed(0)}%
                  </span>
                </div>
                <p className="text-xs sm:text-sm font-medium text-gray-700">{func.name}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* High Priority Items */}
      {gaps && gaps.high_priority_items.length > 0 && (
        <div className="bg-white rounded-lg shadow p-4 sm:p-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3 sm:mb-4">
            <h2 className="text-base sm:text-lg font-semibold text-gray-900">High Priority Items</h2>
            <Link
              to="/recommendations"
              className="text-sm text-blue-600 hover:text-blue-700"
            >
              View all →
            </Link>
          </div>
          <div className="space-y-2 sm:space-y-3">
            {gaps.high_priority_items.slice(0, 5).map((item, idx) => (
              <div
                key={idx}
                className="flex items-start p-2 sm:p-3 bg-gray-50 rounded-lg"
              >
                <div
                  className={`flex-shrink-0 w-2 h-2 mt-1.5 sm:mt-2 rounded-full ${
                    item.severity === 'high' ? 'bg-red-500' : 'bg-yellow-500'
                  }`}
                />
                <div className="ml-2 sm:ml-3 min-w-0">
                  <p className="text-xs sm:text-sm font-medium text-gray-900 truncate">{item.name}</p>
                  <p className="text-xs sm:text-sm text-gray-500 line-clamp-2">{item.recommendation}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Quick Actions */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 sm:gap-4">
        <Link
          to="/ingest"
          className="bg-white rounded-lg shadow p-4 sm:p-6 hover:shadow-lg transition-shadow"
        >
          <div className="flex items-center">
            <TrendingUp className="h-6 w-6 sm:h-8 sm:w-8 text-blue-500 flex-shrink-0" />
            <div className="ml-3 sm:ml-4 min-w-0">
              <p className="text-sm sm:text-lg font-medium text-gray-900">Import Detections</p>
              <p className="text-xs sm:text-sm text-gray-500 truncate">Upload CSV, YAML, or paste</p>
            </div>
          </div>
        </Link>
        <Link
          to="/attack-coverage"
          className="bg-white rounded-lg shadow p-4 sm:p-6 hover:shadow-lg transition-shadow"
        >
          <div className="flex items-center">
            <Target className="h-6 w-6 sm:h-8 sm:w-8 text-purple-500 flex-shrink-0" />
            <div className="ml-3 sm:ml-4 min-w-0">
              <p className="text-sm sm:text-lg font-medium text-gray-900">ATT&CK Matrix</p>
              <p className="text-xs sm:text-sm text-gray-500 truncate">View technique coverage</p>
            </div>
          </div>
        </Link>
        <Link
          to="/csf-posture"
          className="bg-white rounded-lg shadow p-4 sm:p-6 hover:shadow-lg transition-shadow"
        >
          <div className="flex items-center">
            <CheckCircle className="h-6 w-6 sm:h-8 sm:w-8 text-green-500 flex-shrink-0" />
            <div className="ml-3 sm:ml-4 min-w-0">
              <p className="text-sm sm:text-lg font-medium text-gray-900">CSF Report</p>
              <p className="text-xs sm:text-sm text-gray-500 truncate">View compliance posture</p>
            </div>
          </div>
        </Link>
      </div>

      {/* Admin Actions */}
      <div className="bg-white rounded-lg shadow p-4 sm:p-6">
        <h2 className="text-base sm:text-lg font-semibold text-gray-900 mb-3 sm:mb-4">Admin Actions</h2>
        <div className="flex flex-wrap gap-3">
          <button
            onClick={() => setShowReprocessModal(true)}
            className="inline-flex items-center px-4 py-2 bg-orange-100 text-orange-700 rounded-lg hover:bg-orange-200 transition-colors"
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Reprocess All Mappings
          </button>
          <p className="text-xs sm:text-sm text-gray-500 self-center">
            Re-run the enhanced MITRE mapper on all detections
          </p>
        </div>
      </div>

      {/* Reprocess Modal */}
      <ReprocessModal
        isOpen={showReprocessModal}
        onClose={handleCloseModal}
        onConfirm={handleReprocess}
        isLoading={reprocessMutation.isPending}
        result={reprocessResult}
      />
    </div>
  );
}
