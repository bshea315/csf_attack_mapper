import { useQuery } from '@tanstack/react-query';
import { analyticsApi } from '../api/client';
import { AlertTriangle, TrendingUp, Shield, Target, Lightbulb } from 'lucide-react';
import clsx from 'clsx';

const priorityColors: Record<string, { bg: string; text: string; icon: string }> = {
  critical: { bg: 'bg-red-50', text: 'text-red-800', icon: 'text-red-500' },
  high: { bg: 'bg-orange-50', text: 'text-orange-800', icon: 'text-orange-500' },
  medium: { bg: 'bg-yellow-50', text: 'text-yellow-800', icon: 'text-yellow-500' },
  low: { bg: 'bg-green-50', text: 'text-green-800', icon: 'text-green-500' },
};

const categoryIcons: Record<string, React.ElementType> = {
  coverage_gap: Target,
  csf_weakness: Shield,
  improvement: TrendingUp,
  default: Lightbulb,
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

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Recommendations</h1>
        <p className="text-gray-600">
          Prioritized actions to improve your detection coverage
        </p>
      </div>

      {/* Summary Cards */}
      {gaps && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-white rounded-lg shadow p-4">
            <div className="flex items-center">
              <AlertTriangle className="h-8 w-8 text-red-500" />
              <div className="ml-3">
                <p className="text-sm text-gray-500">Total Gaps</p>
                <p className="text-2xl font-bold">{gaps.total_gaps}</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <div className="flex items-center">
              <Target className="h-8 w-8 text-purple-500" />
              <div className="ml-3">
                <p className="text-sm text-gray-500">Uncovered Techniques</p>
                <p className="text-2xl font-bold">{gaps.uncovered_technique_count}</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <div className="flex items-center">
              <Shield className="h-8 w-8 text-orange-500" />
              <div className="ml-3">
                <p className="text-sm text-gray-500">Low CSF Coverage</p>
                <p className="text-2xl font-bold">{gaps.low_csf_coverage_count}</p>
              </div>
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-4">
            <div className="flex items-center">
              <AlertTriangle className="h-8 w-8 text-red-600" />
              <div className="ml-3">
                <p className="text-sm text-gray-500">Critical Gaps</p>
                <p className="text-2xl font-bold">{gaps.critical_gaps}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Recommendations List */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">
            Top Recommendations
          </h2>
          <p className="text-sm text-gray-500">
            Actions ranked by impact and effort
          </p>
        </div>
        <div className="divide-y divide-gray-200">
          {data && data.length > 0 ? (
            data.map((rec, idx) => {
              const colors = priorityColors[rec.priority] || priorityColors.medium;
              const Icon = categoryIcons[rec.category] || categoryIcons.default;
              return (
                <div key={idx} className={clsx('p-6', colors.bg)}>
                  <div className="flex items-start gap-4">
                    <div className={clsx('p-2 rounded-lg', colors.bg)}>
                      <Icon className={clsx('h-6 w-6', colors.icon)} />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={clsx(
                          'px-2 py-0.5 text-xs font-medium rounded',
                          colors.bg,
                          colors.text
                        )}>
                          {rec.priority.toUpperCase()}
                        </span>
                        <span className="text-xs text-gray-500">
                          {rec.category.replace('_', ' ')}
                        </span>
                      </div>
                      <h3 className="text-lg font-medium text-gray-900">
                        {rec.title}
                      </h3>
                      <p className="mt-1 text-gray-600">{rec.description}</p>

                      {/* Evidence */}
                      {rec.evidence && rec.evidence.length > 0 && (
                        <div className="mt-3">
                          <p className="text-sm font-medium text-gray-700 mb-1">
                            Evidence:
                          </p>
                          <ul className="list-disc list-inside text-sm text-gray-600 space-y-1">
                            {rec.evidence.map((ev, evIdx) => (
                              <li key={evIdx}>{ev}</li>
                            ))}
                          </ul>
                        </div>
                      )}

                      {/* Impact and Effort */}
                      <div className="mt-3 flex items-center gap-4 text-sm">
                        {rec.estimated_impact && (
                          <span className="text-gray-600">
                            <span className="font-medium">Impact:</span>{' '}
                            {rec.estimated_impact}
                          </span>
                        )}
                        {rec.effort && (
                          <span className="text-gray-600">
                            <span className="font-medium">Effort:</span>{' '}
                            {rec.effort}
                          </span>
                        )}
                      </div>

                      {/* Related Items */}
                      {rec.related_techniques && rec.related_techniques.length > 0 && (
                        <div className="mt-3 flex flex-wrap gap-1">
                          {rec.related_techniques.slice(0, 5).map((tech) => (
                            <span
                              key={tech}
                              className="px-2 py-1 text-xs bg-gray-100 text-gray-700 rounded"
                            >
                              {tech}
                            </span>
                          ))}
                          {rec.related_techniques.length > 5 && (
                            <span className="px-2 py-1 text-xs bg-gray-100 text-gray-500 rounded">
                              +{rec.related_techniques.length - 5} more
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })
          ) : (
            <div className="p-6 text-center text-gray-500">
              <Lightbulb className="h-12 w-12 mx-auto mb-2 text-gray-400" />
              <p>No recommendations at this time.</p>
              <p className="text-sm">Import some detections to get started!</p>
            </div>
          )}
        </div>
      </div>

      {/* Uncovered Tactics */}
      {gaps && gaps.uncovered_tactics && gaps.uncovered_tactics.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Uncovered Tactics
          </h2>
          <p className="text-sm text-gray-600 mb-4">
            These MITRE ATT&CK tactics have no detection coverage
          </p>
          <div className="flex flex-wrap gap-2">
            {gaps.uncovered_tactics.map((tactic) => (
              <span
                key={tactic}
                className="px-3 py-2 bg-red-100 text-red-800 rounded-lg font-medium"
              >
                {tactic.replace(/-/g, ' ').toUpperCase()}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Low Coverage CSF Categories */}
      {gaps && gaps.low_coverage_csf && gaps.low_coverage_csf.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Low Coverage CSF Categories
          </h2>
          <p className="text-sm text-gray-600 mb-4">
            These CSF categories have less than 30% coverage
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {gaps.low_coverage_csf.map((cat) => (
              <div
                key={cat.csf_id}
                className="p-3 bg-orange-50 rounded-lg"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-medium text-gray-900">{cat.csf_id}</span>
                  <span className="text-sm text-orange-700">
                    {(cat.coverage * 100).toFixed(0)}%
                  </span>
                </div>
                <p className="text-sm text-gray-600">{cat.name}</p>
                <div className="mt-2 h-2 bg-orange-200 rounded-full overflow-hidden">
                  <div
                    className="h-full bg-orange-500 rounded-full"
                    style={{ width: `${cat.coverage * 100}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
