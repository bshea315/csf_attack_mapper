import { useQuery } from '@tanstack/react-query';
import { analyticsApi, exportsApi } from '../api/client';
import { AlertTriangle, Shield, Target, Lightbulb, Download, CheckCircle, Wrench } from 'lucide-react';
import clsx from 'clsx';
import { Link } from 'react-router-dom';

// Convert numeric priority to string level
const getPriorityLevel = (priority: number): string => {
  if (priority <= 2) return 'critical';
  if (priority <= 5) return 'high';
  if (priority <= 8) return 'medium';
  return 'low';
};

const priorityColors: Record<string, { bg: string; text: string; icon: string; border: string }> = {
  critical: { bg: 'bg-red-50', text: 'text-red-800', icon: 'text-red-500', border: 'border-red-200' },
  high: { bg: 'bg-orange-50', text: 'text-orange-800', icon: 'text-orange-500', border: 'border-orange-200' },
  medium: { bg: 'bg-yellow-50', text: 'text-yellow-800', icon: 'text-yellow-500', border: 'border-yellow-200' },
  low: { bg: 'bg-green-50', text: 'text-green-800', icon: 'text-green-500', border: 'border-green-200' },
};

const typeIcons: Record<string, React.ElementType> = {
  add_detection: Target,
  tune_detection: Wrench,
  enable_detection: CheckCircle,
  default: Lightbulb,
};

const typeLabels: Record<string, string> = {
  add_detection: 'Add Detection',
  tune_detection: 'Tune Detection',
  enable_detection: 'Enable Detection',
};

export default function Recommendations() {
  const { data, isLoading } = useQuery({
    queryKey: ['recommendations'],
    queryFn: analyticsApi.getRecommendations,
  });

  const { data: gaps } = useQuery({
    queryKey: ['gaps'],
    queryFn: analyticsApi.getGaps,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  const recommendations = data?.recommendations || [];

  return (
    <div className="space-y-4 sm:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-gray-900">Recommendations</h1>
          <p className="text-sm sm:text-base text-gray-600">
            Prioritized actions to improve your detection coverage
          </p>
        </div>
        <a
          href={exportsApi.getFullReportJson()}
          className="flex items-center gap-2 px-3 sm:px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm self-start sm:self-auto"
        >
          <Download className="h-4 w-4" />
          <span>Export Report</span>
        </a>
      </div>

      {/* Summary Cards */}
      {gaps && (
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-2 sm:gap-4">
          <div className="bg-white rounded-lg shadow p-3 sm:p-4">
            <div className="flex items-center">
              <AlertTriangle className="h-6 w-6 sm:h-8 sm:w-8 text-red-500 flex-shrink-0" />
              <div className="ml-2 sm:ml-3 min-w-0">
                <p className="text-xs sm:text-sm text-gray-500 truncate">Total Gaps</p>
                <p className="text-xl sm:text-2xl font-bold">{gaps.total_gaps}</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-3 sm:p-4">
            <div className="flex items-center">
              <Target className="h-6 w-6 sm:h-8 sm:w-8 text-purple-500 flex-shrink-0" />
              <div className="ml-2 sm:ml-3 min-w-0">
                <p className="text-xs sm:text-sm text-gray-500 truncate">Technique Gaps</p>
                <p className="text-xl sm:text-2xl font-bold">{gaps.technique_gaps?.length || 0}</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-3 sm:p-4">
            <div className="flex items-center">
              <Shield className="h-6 w-6 sm:h-8 sm:w-8 text-orange-500 flex-shrink-0" />
              <div className="ml-2 sm:ml-3 min-w-0">
                <p className="text-xs sm:text-sm text-gray-500 truncate">CSF Gaps</p>
                <p className="text-xl sm:text-2xl font-bold">{gaps.csf_gaps?.length || 0}</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-3 sm:p-4">
            <div className="flex items-center">
              <AlertTriangle className="h-6 w-6 sm:h-8 sm:w-8 text-red-600 flex-shrink-0" />
              <div className="ml-2 sm:ml-3 min-w-0">
                <p className="text-xs sm:text-sm text-gray-500 truncate">Critical Gaps</p>
                <p className="text-xl sm:text-2xl font-bold">{gaps.critical_gaps}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Recommendations by Type */}
      {data?.by_type && Object.keys(data.by_type).length > 0 && (
        <div className="bg-white rounded-lg shadow p-4 sm:p-6">
          <h2 className="text-base sm:text-lg font-semibold text-gray-900 mb-3 sm:mb-4">
            Recommendations by Type
          </h2>
          <div className="flex flex-wrap gap-2 sm:gap-3">
            {Object.entries(data.by_type).map(([type, count]) => {
              const Icon = typeIcons[type] || typeIcons.default;
              return (
                <div
                  key={type}
                  className="flex items-center gap-2 px-3 py-2 bg-gray-50 rounded-lg"
                >
                  <Icon className="h-4 w-4 sm:h-5 sm:w-5 text-gray-600" />
                  <span className="text-xs sm:text-sm font-medium text-gray-900">
                    {typeLabels[type] || type.replace(/_/g, ' ')}
                  </span>
                  <span className="px-2 py-0.5 text-xs bg-blue-100 text-blue-800 rounded-full">
                    {count}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Recommendations List */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-4 sm:px-6 py-3 sm:py-4 border-b border-gray-200">
          <h2 className="text-base sm:text-lg font-semibold text-gray-900">
            Top Recommendations
          </h2>
          <p className="text-xs sm:text-sm text-gray-500">
            Actions ranked by impact - {recommendations.length} recommendations
          </p>
        </div>
        <div className="divide-y divide-gray-200">
          {recommendations.length > 0 ? (
            recommendations.map((rec, idx) => {
              const priorityLevel = getPriorityLevel(rec.priority);
              const colors = priorityColors[priorityLevel] || priorityColors.medium;
              const Icon = typeIcons[rec.type] || typeIcons.default;
              return (
                <div key={rec.id || idx} className={clsx('p-4 sm:p-6', colors.bg)}>
                  <div className="flex flex-col sm:flex-row sm:items-start gap-3 sm:gap-4">
                    <div className={clsx('p-2 rounded-lg self-start', 'bg-white border', colors.border)}>
                      <Icon className={clsx('h-5 w-5 sm:h-6 sm:w-6', colors.icon)} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2 mb-1">
                        <span className="text-xs font-medium text-gray-500">
                          #{rec.priority}
                        </span>
                        <span className={clsx(
                          'px-2 py-0.5 text-xs font-medium rounded',
                          colors.text,
                          'bg-white border',
                          colors.border
                        )}>
                          {priorityLevel.toUpperCase()}
                        </span>
                        <span className="px-2 py-0.5 text-xs bg-gray-100 text-gray-600 rounded">
                          {typeLabels[rec.type] || rec.type.replace(/_/g, ' ')}
                        </span>
                      </div>
                      <h3 className="text-sm sm:text-lg font-medium text-gray-900 break-words">
                        {rec.title}
                      </h3>
                      <p className="mt-1 text-xs sm:text-sm text-gray-600 line-clamp-2">{rec.description}</p>

                      {/* Evidence */}
                      {rec.evidence && rec.evidence.length > 0 && (
                        <div className="mt-2 sm:mt-3">
                          <p className="text-xs sm:text-sm font-medium text-gray-700 mb-1">
                            Evidence:
                          </p>
                          <ul className="list-disc list-inside text-xs sm:text-sm text-gray-600 space-y-0.5">
                            {rec.evidence.map((ev, evIdx) => (
                              <li key={evIdx} className="break-words">{ev}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Impact and Links */}
                      <div className="mt-2 sm:mt-3 flex flex-wrap items-center gap-2 sm:gap-4 text-xs sm:text-sm">
                        {rec.impact_estimate && (
                          <span className="text-gray-600">
                            <span className="font-medium">Impact:</span>{' '}
                            +{(rec.impact_estimate * 100).toFixed(0)}% coverage
                          </span>
                        )}
                        {rec.detection_id && (
                          <Link
                            to={`/detections/${rec.detection_id}`}
                            className="text-blue-600 hover:text-blue-700"
                          >
                            View Detection →
                          </Link>
                        )}
                      </div>

                      {/* Related Techniques */}
                      {rec.affected_techniques && rec.affected_techniques.length > 0 && (
                        <div className="mt-2 sm:mt-3 flex flex-wrap gap-1">
                          {rec.affected_techniques.slice(0, 5).map((tech) => (
                            <span
                              key={tech}
                              className="px-2 py-1 text-xs bg-purple-100 text-purple-700 rounded"
                            >
                              {tech}
                            </span>
                          ))}
                          {rec.affected_techniques.length > 5 && (
                            <span className="px-2 py-1 text-xs bg-gray-100 text-gray-500 rounded">
                              +{rec.affected_techniques.length - 5} more
                            </span>
                          )}
                        </div>
                      )}

                      {/* Related CSF */}
                      {rec.affected_csf && rec.affected_csf.length > 0 && (
                        <div className="mt-2 flex flex-wrap gap-1">
                          {rec.affected_csf.map((csf) => (
                            <span
                              key={csf}
                              className="px-2 py-1 text-xs bg-green-100 text-green-700 rounded"
                            >
                              {csf}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="p-6 sm:p-8 text-center text-gray-500">
              <Lightbulb className="h-10 w-10 sm:h-12 sm:w-12 mx-auto mb-2 text-gray-400" />
              <p className="text-sm sm:text-base">No recommendations at this time.</p>
              <p className="text-xs sm:text-sm mt-1">Import some detections to get started!</p>
              <Link
                to="/ingest"
                className="inline-block mt-4 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm"
              >
                Import Detections
              </Link>
            </div>
          )}
        </div>
      </div>

      {/* Technique Gaps Section */}
      {gaps && gaps.technique_gaps && gaps.technique_gaps.length > 0 && (
        <div className="bg-white rounded-lg shadow p-4 sm:p-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3 sm:mb-4">
            <div>
              <h2 className="text-base sm:text-lg font-semibold text-gray-900">
                Uncovered Techniques
              </h2>
              <p className="text-xs sm:text-sm text-gray-600">
                MITRE ATT&CK techniques with no detection coverage
              </p>
            </div>
            <Link
              to="/attack-coverage"
              className="text-xs sm:text-sm text-blue-600 hover:text-blue-700"
            >
              View ATT&CK Matrix →
            </Link>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 sm:gap-3">
            {gaps.technique_gaps.slice(0, 9).map((gap) => (
              <div
                key={gap.id}
                className={clsx(
                  'p-3 rounded-lg border',
                  gap.severity === 'high' ? 'bg-red-50 border-red-200' : 'bg-yellow-50 border-yellow-200'
                )}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs sm:text-sm font-medium text-gray-900">{gap.id}</span>
                  <span className={clsx(
                    'px-2 py-0.5 text-xs rounded',
                    gap.severity === 'high' ? 'bg-red-100 text-red-700' : 'bg-yellow-100 text-yellow-700'
                  )}>
                    {gap.severity}
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-gray-700 line-clamp-2">{gap.name}</p>
              </div>
            ))}
          </div>
          {gaps.technique_gaps.length > 9 && (
            <div className="mt-3 text-center">
              <span className="text-xs sm:text-sm text-gray-500">
                +{gaps.technique_gaps.length - 9} more uncovered techniques
              </span>
            </div>
          )}
        </div>
      )}

      {/* CSF Gaps Section */}
      {gaps && gaps.csf_gaps && gaps.csf_gaps.length > 0 && (
        <div className="bg-white rounded-lg shadow p-4 sm:p-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3 sm:mb-4">
            <div>
              <h2 className="text-base sm:text-lg font-semibold text-gray-900">
                Low Coverage CSF Categories
              </h2>
              <p className="text-xs sm:text-sm text-gray-600">
                NIST CSF categories that need more detection coverage
              </p>
            </div>
            <Link
              to="/csf-posture"
              className="text-xs sm:text-sm text-blue-600 hover:text-blue-700"
            >
              View CSF Posture →
            </Link>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 sm:gap-3">
            {gaps.csf_gaps.slice(0, 6).map((gap) => (
              <div
                key={gap.id}
                className="p-3 bg-orange-50 border border-orange-200 rounded-lg"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs sm:text-sm font-medium text-gray-900">{gap.id}</span>
                  <span className={clsx(
                    'px-2 py-0.5 text-xs rounded',
                    gap.severity === 'high' ? 'bg-red-100 text-red-700' : 'bg-orange-100 text-orange-700'
                  )}>
                    {gap.severity}
                  </span>
                </div>
                <p className="text-xs sm:text-sm text-gray-700 line-clamp-2">{gap.name}</p>
                <p className="text-xs text-gray-500 mt-1 line-clamp-1">{gap.recommendation}</p>
              </div>
            ))}
          </div>
          {gaps.csf_gaps.length > 6 && (
            <div className="mt-3 text-center">
              <span className="text-xs sm:text-sm text-gray-500">
                +{gaps.csf_gaps.length - 6} more low-coverage categories
              </span>
            </div>
          )}
        </div>
      )}

      {/* Quality Issues Section */}
      {gaps && gaps.quality_issues && gaps.quality_issues.length > 0 && (
        <div className="bg-white rounded-lg shadow p-4 sm:p-6">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 mb-3 sm:mb-4">
            <div>
              <h2 className="text-base sm:text-lg font-semibold text-gray-900">
                Detection Quality Issues
              </h2>
              <p className="text-xs sm:text-sm text-gray-600">
                Detections that could be improved
              </p>
            </div>
            <Link
              to="/detections"
              className="text-xs sm:text-sm text-blue-600 hover:text-blue-700"
            >
              View All Detections →
            </Link>
          </div>
          <div className="space-y-2">
            {gaps.quality_issues.slice(0, 5).map((issue) => (
              <div
                key={issue.id}
                className={clsx(
                  'flex flex-col sm:flex-row sm:items-center justify-between p-3 rounded-lg border gap-2',
                  issue.severity === 'high' ? 'bg-red-50 border-red-200' : 'bg-gray-50 border-gray-200'
                )}
              >
                <div className="flex-1 min-w-0">
                  <p className="text-xs sm:text-sm font-medium text-gray-900 truncate">{issue.name}</p>
                  <p className="text-xs text-gray-500 truncate">{issue.description}</p>
                </div>
                {issue.detection_id && (
                  <Link
                    to={`/detections/${issue.detection_id}`}
                    className="text-xs sm:text-sm text-blue-600 hover:text-blue-700 whitespace-nowrap"
                  >
                    View →
                  </Link>
                )}
              </div>
            ))}
          </div>
          {gaps.quality_issues.length > 5 && (
            <div className="mt-3 text-center">
              <span className="text-xs sm:text-sm text-gray-500">
                +{gaps.quality_issues.length - 5} more quality issues
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
