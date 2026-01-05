import { useQuery } from '@tanstack/react-query';
import { analyticsApi, exportsApi } from '../api/client';
import { Download } from 'lucide-react';
import clsx from 'clsx';

const functionColors: Record<string, { bg: string; border: string }> = {
  GOVERN: { bg: 'bg-csf-govern', border: 'border-csf-govern' },
  IDENTIFY: { bg: 'bg-csf-identify', border: 'border-csf-identify' },
  PROTECT: { bg: 'bg-csf-protect', border: 'border-csf-protect' },
  DETECT: { bg: 'bg-csf-detect', border: 'border-csf-detect' },
  RESPOND: { bg: 'bg-csf-respond', border: 'border-csf-respond' },
  RECOVER: { bg: 'bg-csf-recover', border: 'border-csf-recover' },
};

export default function CsfPosture() {
  const { data, isLoading } = useQuery({
    queryKey: ['csf-coverage'],
    queryFn: analyticsApi.getCsfCoverage,
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
          <h1 className="text-2xl font-bold text-gray-900">CSF 2.0 Posture</h1>
          <p className="text-gray-600">
            Overall coverage score: {(data.overall_score * 100).toFixed(0)}%
          </p>
        </div>
        <a
          href={exportsApi.getCsfPostureCsv()}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
        >
          <Download className="h-4 w-4" />
          Export CSV
        </a>
      </div>

      {/* Function Overview */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {data.functions.map((func) => {
          const colors = functionColors[func.function] || { bg: 'bg-gray-500', border: 'border-gray-500' };
          return (
            <div
              key={func.function}
              className={clsx('bg-white rounded-lg shadow p-4 border-t-4', colors.border)}
            >
              <h3 className="font-semibold text-gray-900">{func.function}</h3>
              <div className="mt-2">
                <div className="flex items-end gap-1">
                  <span className="text-3xl font-bold">
                    {(func.average_score * 100).toFixed(0)}
                  </span>
                  <span className="text-gray-500 mb-1">%</span>
                </div>
                <p className="text-sm text-gray-500">
                  {func.covered_subcategories} of {func.total_subcategories} categories
                </p>
                <p className="text-sm text-gray-500">
                  {func.detection_count} detections
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Detailed Categories */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200">
          <h2 className="text-lg font-semibold text-gray-900">Category Details</h2>
        </div>
        <div className="divide-y divide-gray-200">
          {data.functions.map((func) => {
            const colors = functionColors[func.function] || { bg: 'bg-gray-500', border: 'border-gray-500' };
            return (
              <div key={func.function} className="p-6">
                <div className="flex items-center gap-3 mb-4">
                  <span className={clsx('px-3 py-1 text-white text-sm font-medium rounded', colors.bg)}>
                    {func.function}
                  </span>
                  <span className="text-gray-500">
                    Average: {(func.average_score * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                  {func.categories.map((cat) => (
                    <div
                      key={cat.id}
                      className="p-3 bg-gray-50 rounded-lg"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-medium text-gray-900">{cat.id}</span>
                        <span className={clsx(
                          'px-2 py-1 text-xs rounded',
                          cat.score > 0.5 ? 'bg-green-100 text-green-800' :
                          cat.score > 0.2 ? 'bg-yellow-100 text-yellow-800' :
                          cat.score > 0 ? 'bg-red-100 text-red-800' :
                          'bg-gray-100 text-gray-800'
                        )}>
                          {(cat.score * 100).toFixed(0)}%
                        </span>
                      </div>
                      <p className="text-sm text-gray-600">{cat.name}</p>
                      <p className="text-xs text-gray-400 mt-1">
                        {cat.detection_count} detection{cat.detection_count !== 1 ? 's' : ''}
                      </p>
                      {/* Progress bar */}
                      <div className="mt-2 h-2 bg-gray-200 rounded-full overflow-hidden">
                        <div
                          className={clsx('h-full rounded-full', colors.bg)}
                          style={{ width: `${cat.score * 100}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
