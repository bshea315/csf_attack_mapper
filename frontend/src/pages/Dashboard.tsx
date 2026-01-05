import { useQuery } from '@tanstack/react-query';
import { analyticsApi } from '../api/client';
import { Link } from 'react-router-dom';
import {
  FileSearch,
  Target,
  Shield,
  AlertTriangle,
  TrendingUp,
  CheckCircle,
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
    <div className="bg-white rounded-lg shadow p-6">
      <div className="flex items-center">
        <div className={`p-3 rounded-lg ${color}`}>
          <Icon className="h-6 w-6 text-white" />
        </div>
        <div className="ml-4">
          <p className="text-sm font-medium text-gray-500">{title}</p>
          <p className="text-2xl font-semibold text-gray-900">{value}</p>
          {subtitle && <p className="text-sm text-gray-500">{subtitle}</p>}
        </div>
      </div>
    </div>
  );
}

export default function Dashboard() {
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

  if (overviewLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Dashboard</h1>
        <p className="text-gray-600">Detection coverage overview and key metrics</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
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
        <div className="bg-white rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">CSF 2.0 Function Coverage</h2>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
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
                  className={`mx-auto w-16 h-16 rounded-full ${func.color} flex items-center justify-center mb-2`}
                >
                  <span className="text-white font-bold">
                    {(func.score * 100).toFixed(0)}%
                  </span>
                </div>
                <p className="text-sm font-medium text-gray-700">{func.name}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* High Priority Items */}
      {gaps && gaps.high_priority_items.length > 0 && (
        <div className="bg-white rounded-lg shadow p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-gray-900">High Priority Items</h2>
            <Link
              to="/recommendations"
              className="text-sm text-blue-600 hover:text-blue-700"
            >
              View all recommendations →
            </Link>
          </div>
          <div className="space-y-3">
            {gaps.high_priority_items.slice(0, 5).map((item, idx) => (
              <div
                key={idx}
                className="flex items-start p-3 bg-gray-50 rounded-lg"
              >
                <div
                  className={`flex-shrink-0 w-2 h-2 mt-2 rounded-full ${
                    item.severity === 'high' ? 'bg-red-500' : 'bg-yellow-500'
                  }`}
                />
                <div className="ml-3">
                  <p className="text-sm font-medium text-gray-900">{item.name}</p>
                  <p className="text-sm text-gray-500">{item.recommendation}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Link
          to="/ingest"
          className="bg-white rounded-lg shadow p-6 hover:shadow-lg transition-shadow"
        >
          <div className="flex items-center">
            <TrendingUp className="h-8 w-8 text-blue-500" />
            <div className="ml-4">
              <p className="text-lg font-medium text-gray-900">Import Detections</p>
              <p className="text-sm text-gray-500">Upload CSV, YAML, or paste</p>
            </div>
          </div>
        </Link>
        <Link
          to="/attack-coverage"
          className="bg-white rounded-lg shadow p-6 hover:shadow-lg transition-shadow"
        >
          <div className="flex items-center">
            <Target className="h-8 w-8 text-purple-500" />
            <div className="ml-4">
              <p className="text-lg font-medium text-gray-900">ATT&CK Matrix</p>
              <p className="text-sm text-gray-500">View technique coverage</p>
            </div>
          </div>
        </Link>
        <Link
          to="/csf-posture"
          className="bg-white rounded-lg shadow p-6 hover:shadow-lg transition-shadow"
        >
          <div className="flex items-center">
            <CheckCircle className="h-8 w-8 text-green-500" />
            <div className="ml-4">
              <p className="text-lg font-medium text-gray-900">CSF Report</p>
              <p className="text-sm text-gray-500">View compliance posture</p>
            </div>
          </div>
        </Link>
      </div>
    </div>
  );
}
