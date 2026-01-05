import { useQuery } from '@tanstack/react-query';
import { analyticsApi, exportsApi } from '../api/client';
import { Download } from 'lucide-react';
import clsx from 'clsx';

function getCoverageColor(count: number): string {
  if (count === 0) return 'bg-gray-100 text-gray-400';
  if (count === 1) return 'bg-red-100 text-red-800';
  if (count <= 3) return 'bg-yellow-100 text-yellow-800';
  if (count <= 5) return 'bg-green-100 text-green-800';
  return 'bg-green-200 text-green-900';
}

export default function AttackCoverage() {
  const { data, isLoading } = useQuery({
    queryKey: ['attack-coverage'],
    queryFn: analyticsApi.getAttackCoverage,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">ATT&CK Coverage</h1>
          <p className="text-gray-600">
            {data.covered_techniques} of {data.total_techniques} techniques covered ({data.coverage_percentage.toFixed(0)}%)
          </p>
        </div>
        <a
          href={exportsApi.getAttackCoverageCsv()}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <Download className="h-4 w-4" />
          Export CSV
        </a>
      </div>

      {/* Legend */}
      <div className="bg-white rounded-lg shadow p-4 flex items-center gap-6">
        <span className="text-sm font-medium text-gray-700">Coverage:</span>
        <div className="flex items-center gap-2">
          <span className="w-6 h-6 bg-gray-100 rounded" />
          <span className="text-sm text-gray-600">None</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-6 h-6 bg-red-100 rounded" />
          <span className="text-sm text-gray-600">1</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-6 h-6 bg-yellow-100 rounded" />
          <span className="text-sm text-gray-600">2-3</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-6 h-6 bg-green-100 rounded" />
          <span className="text-sm text-gray-600">4-5</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-6 h-6 bg-green-200 rounded" />
          <span className="text-sm text-gray-600">6+</span>
        </div>
      </div>

      {/* Matrix */}
      <div className="bg-white rounded-lg shadow overflow-x-auto">
        <div className="min-w-max p-4">
          <div className="grid grid-cols-14 gap-1">
            {data.tactics.map((tactic) => {
              const techniques = data.techniques_by_tactic[tactic] || [];
              return (
                <div key={tactic} className="min-w-[120px]">
                  <div className="p-2 bg-gray-800 text-white text-xs font-medium text-center rounded-t">
                    {tactic.replace(/-/g, ' ').toUpperCase()}
                  </div>
                  <div className="space-y-1 p-1 bg-gray-50 min-h-[300px]">
                    {techniques.slice(0, 20).map((tech) => (
                      <div
                        key={tech.technique_id}
                        className={clsx(
                          'p-2 rounded text-xs cursor-pointer hover:opacity-80 transition-opacity',
                          getCoverageColor(tech.detection_count)
                        )}
                        title={`${tech.technique_name}: ${tech.detection_count} detections`}
                      >
                        <p className="font-medium truncate">{tech.technique_id}</p>
                        <p className="truncate opacity-75">{tech.technique_name}</p>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Top Covered */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Top Covered Techniques</h2>
          <div className="space-y-2">
            {data.top_covered.slice(0, 10).map((tech) => (
              <div key={tech.technique_id} className="flex items-center justify-between">
                <div>
                  <span className="font-medium">{tech.technique_id}</span>
                  <span className="text-gray-500 ml-2">{tech.technique_name}</span>
                </div>
                <span className="px-2 py-1 bg-green-100 text-green-800 text-sm rounded">
                  {tech.detection_count} detections
                </span>
              </div>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Uncovered Techniques</h2>
          <div className="space-y-2 max-h-[400px] overflow-y-auto">
            {data.uncovered.slice(0, 20).map((tech) => (
              <div key={tech.technique_id} className="flex items-center justify-between text-sm">
                <div>
                  <span className="font-medium">{tech.technique_id}</span>
                  <span className="text-gray-500 ml-2">{tech.technique_name}</span>
                </div>
                <span className="px-2 py-1 bg-red-100 text-red-800 rounded">
                  No coverage
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
