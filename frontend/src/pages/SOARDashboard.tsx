import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  LineChart,
  Line,
  Legend,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import { playbooksApi } from '../api/client';
import type { ActionMetrics, PlaybookRun, AppMetrics } from '../types';

const COLORS = ['#22c55e', '#ef4444', '#f59e0b', '#3b82f6', '#8b5cf6', '#ec4899'];

export default function SOARDashboard() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['soar-dashboard'],
    queryFn: playbooksApi.getDashboard,
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-gray-500">Loading SOAR dashboard...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-6xl mx-auto p-6">
        <div className="bg-red-50 text-red-600 p-4 rounded">
          Error loading dashboard: {(error as Error).message}
        </div>
      </div>
    );
  }

  if (!data) {
    return null;
  }

  return (
    <div className="max-w-7xl mx-auto p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">SOAR Dashboard</h1>
        <Link
          to="/playbooks"
          className="px-4 py-2 border rounded hover:bg-gray-50"
        >
          View All Playbooks
        </Link>
      </div>

      {/* Time Savings Hero Section */}
      <div className="bg-gradient-to-r from-purple-600 to-indigo-600 rounded-lg shadow-lg p-6 mb-6 text-white">
        <div className="grid grid-cols-3 gap-6">
          <div>
            <p className="text-purple-200 text-sm">Total Time Saved</p>
            <p className="text-4xl font-bold">{data.overview.total_time_saved_hours.toFixed(1)}h</p>
            <p className="text-purple-200 text-xs mt-1">
              {data.overview.total_time_saved_minutes.toFixed(0)} minutes total
            </p>
          </div>
          <div>
            <p className="text-purple-200 text-sm">Estimated Cost Savings</p>
            <p className="text-4xl font-bold">${data.overview.estimated_cost_savings.toLocaleString()}</p>
            <p className="text-purple-200 text-xs mt-1">Based on $75/hr analyst rate</p>
          </div>
          <div>
            <p className="text-purple-200 text-sm">Automation Coverage</p>
            <p className="text-4xl font-bold">{data.overview.automation_coverage_percent.toFixed(1)}%</p>
            <p className="text-purple-200 text-xs mt-1">
              {data.overview.linked_detections} of {data.overview.linked_detections + data.overview.unlinked_detections} detections
            </p>
          </div>
        </div>
      </div>

      {/* Overview Stats */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        <StatCard
          title="Total Playbooks"
          value={data.overview.total_playbooks}
          subtitle={`${data.overview.active_playbooks} active`}
        />
        <StatCard
          title="Total Runs"
          value={data.overview.total_runs}
          subtitle={`${data.overview.runs_last_24h} in last 24h`}
        />
        <StatCard
          title="Success Rate"
          value={`${data.overview.overall_success_rate.toFixed(1)}%`}
          subtitle={`${data.overview.successful_runs} successful`}
          valueColor={
            data.overview.overall_success_rate >= 90
              ? 'text-green-600'
              : data.overview.overall_success_rate >= 70
              ? 'text-yellow-600'
              : 'text-red-600'
          }
        />
        <StatCard
          title="MTTR"
          value={data.overview.mttr_minutes ? `${data.overview.mttr_minutes.toFixed(1)}m` : '-'}
          subtitle="Mean Time to Respond"
        />
        <StatCard
          title="Automation Rate"
          value={`${data.overview.automation_rate.toFixed(1)}%`}
          subtitle={`${data.overview.cancelled_runs} cancelled`}
        />
      </div>

      {/* Time Saved by Playbook */}
      {data.time_saved_by_playbook.length > 0 && (
        <div className="bg-white rounded-lg shadow mb-6">
          <div className="p-4 border-b flex justify-between items-center">
            <h2 className="text-lg font-semibold">Time Saved by Playbook</h2>
            <span className="text-sm text-gray-500">
              {data.overview.playbooks_with_time_config} playbooks with time configured
            </span>
          </div>
          <div className="p-4">
            <ResponsiveContainer width="100%" height={300}>
              <BarChart
                data={data.time_saved_by_playbook.slice(0, 10)}
                layout="vertical"
                margin={{ left: 150 }}
              >
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis type="number" unit="h" />
                <YAxis
                  type="category"
                  dataKey="playbook_name"
                  tick={{ fontSize: 11 }}
                  width={150}
                />
                <Tooltip
                  formatter={(value: number) => [`${value.toFixed(1)} hours`, 'Time Saved']}
                  labelFormatter={(name) => `Playbook: ${name}`}
                />
                <Bar dataKey="total_time_saved_hours" name="Hours Saved" fill="#8b5cf6" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Charts Row */}
      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* Time Series Chart */}
        <div className="bg-white rounded-lg shadow p-4">
          <h2 className="text-lg font-semibold mb-4">Run Activity (30 Days)</h2>
          {data.time_series.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <LineChart data={data.time_series}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis
                  dataKey="date"
                  tick={{ fontSize: 12 }}
                  tickFormatter={(date) => new Date(date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip
                  labelFormatter={(date) => new Date(date).toLocaleDateString()}
                />
                <Legend />
                <Line
                  type="monotone"
                  dataKey="success"
                  name="Success"
                  stroke="#22c55e"
                  strokeWidth={2}
                />
                <Line
                  type="monotone"
                  dataKey="failure"
                  name="Failure"
                  stroke="#ef4444"
                  strokeWidth={2}
                />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-500">
              No run data available
            </div>
          )}
        </div>

        {/* Category Breakdown */}
        <div className="bg-white rounded-lg shadow p-4">
          <h2 className="text-lg font-semibold mb-4">Runs by Category</h2>
          {data.category_breakdown.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie
                  data={data.category_breakdown}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={2}
                  dataKey="total_runs"
                  nameKey="category"
                  label={({ category, percent }) => `${category} ${(percent * 100).toFixed(0)}%`}
                >
                  {data.category_breakdown.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip formatter={(value: number) => [value, 'Runs']} />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-64 flex items-center justify-center text-gray-500">
              No category data available
            </div>
          )}
        </div>
      </div>

      {/* Top Playbooks and Apps */}
      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* Top Playbooks */}
        <div className="bg-white rounded-lg shadow">
          <div className="p-4 border-b">
            <h2 className="text-lg font-semibold">Top Playbooks by Runs</h2>
          </div>
          <div className="p-4">
            {data.top_playbooks.length > 0 ? (
              <div className="space-y-3">
                {data.top_playbooks.slice(0, 8).map((pb, i) => (
                  <div key={i} className="flex items-center justify-between py-2 border-b last:border-0">
                    <div className="flex-1">
                      <Link to={`/playbooks/${pb.playbook_id}`} className="font-medium text-sm text-blue-600 hover:underline">
                        {pb.playbook_name}
                      </Link>
                      {pb.category && (
                        <span className="ml-2 text-xs px-2 py-0.5 bg-blue-100 text-blue-800 rounded">
                          {pb.category}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center space-x-4">
                      <span className="text-sm">{pb.total_runs} runs</span>
                      <span className="text-sm text-purple-600 font-medium">
                        {pb.total_time_saved_hours.toFixed(1)}h saved
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="h-64 flex items-center justify-center text-gray-500">
                No playbook data available
              </div>
            )}
          </div>
        </div>

        {/* Top Apps */}
        <div className="bg-white rounded-lg shadow">
          <div className="p-4 border-b">
            <h2 className="text-lg font-semibold">Top Integrations</h2>
          </div>
          <div className="p-4">
            {data.top_apps.length > 0 ? (
              <div className="space-y-3">
                {data.top_apps.slice(0, 8).map((app, i) => (
                  <AppRow key={i} app={app} />
                ))}
              </div>
            ) : (
              <div className="h-64 flex items-center justify-center text-gray-500">
                No app data available
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Top Actions */}
      <div className="bg-white rounded-lg shadow mb-6">
        <div className="p-4 border-b">
          <h2 className="text-lg font-semibold">Top Actions by Runs</h2>
        </div>
        <div className="p-4">
          {data.top_actions.length > 0 ? (
            <div className="grid grid-cols-2 gap-4">
              {data.top_actions.slice(0, 10).map((action, i) => (
                <ActionRow key={i} action={action} />
              ))}
            </div>
          ) : (
            <div className="h-32 flex items-center justify-center text-gray-500">
              No action data available
            </div>
          )}
        </div>
      </div>

      {/* Recent Failures */}
      <div className="bg-white rounded-lg shadow">
        <div className="p-4 border-b">
          <h2 className="text-lg font-semibold">Recent Failures</h2>
        </div>
        <div className="p-4">
          {data.recent_failures.length > 0 ? (
            <div className="space-y-3">
              {data.recent_failures.map((run) => (
                <FailureRow key={run.id} run={run} />
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500">
              No recent failures
            </div>
          )}
        </div>
      </div>

      {/* Additional Metrics */}
      <div className="grid grid-cols-5 gap-4 mt-6">
        <div className="bg-white rounded-lg shadow p-4">
          <p className="text-sm text-gray-500">Total Actions</p>
          <p className="text-2xl font-bold">{data.overview.total_actions.toLocaleString()}</p>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <p className="text-sm text-gray-500">Unique Action Types</p>
          <p className="text-2xl font-bold">{data.overview.unique_action_types}</p>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <p className="text-sm text-gray-500">Integrations Used</p>
          <p className="text-2xl font-bold">{data.overview.unique_apps}</p>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <p className="text-sm text-gray-500">Avg Duration</p>
          <p className="text-2xl font-bold">
            {data.overview.avg_run_duration_seconds
              ? `${data.overview.avg_run_duration_seconds.toFixed(1)}s`
              : '-'}
          </p>
        </div>
        <div className="bg-white rounded-lg shadow p-4">
          <p className="text-sm text-gray-500">Runs (Last 30 Days)</p>
          <p className="text-2xl font-bold">{data.overview.runs_last_30d}</p>
        </div>
      </div>
    </div>
  );
}

// Helper Components
function StatCard({
  title,
  value,
  subtitle,
  valueColor = 'text-gray-900',
}: {
  title: string;
  value: string | number;
  subtitle: string;
  valueColor?: string;
}) {
  return (
    <div className="bg-white rounded-lg shadow p-4">
      <p className="text-sm text-gray-500">{title}</p>
      <p className={`text-2xl font-bold ${valueColor}`}>{value}</p>
      <p className="text-xs text-gray-400">{subtitle}</p>
    </div>
  );
}

function ActionRow({ action }: { action: ActionMetrics }) {
  return (
    <div className="flex items-center justify-between py-2 px-3 bg-gray-50 rounded">
      <div className="flex-1">
        <p className="font-medium text-sm">{action.action_name}</p>
        {action.app_name && (
          <p className="text-xs text-gray-500">{action.app_name}</p>
        )}
      </div>
      <div className="flex items-center space-x-4">
        <span className="text-sm">{action.total_runs} runs</span>
        <div className="w-20">
          <div className="flex items-center">
            <div className="w-12 bg-gray-200 rounded-full h-1.5 mr-2">
              <div
                className={`h-1.5 rounded-full ${
                  action.success_rate >= 90
                    ? 'bg-green-500'
                    : action.success_rate >= 70
                    ? 'bg-yellow-500'
                    : 'bg-red-500'
                }`}
                style={{ width: `${action.success_rate}%` }}
              />
            </div>
            <span className="text-xs">{action.success_rate.toFixed(0)}%</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function AppRow({ app }: { app: AppMetrics }) {
  return (
    <div className="flex items-center justify-between py-2 border-b last:border-0">
      <div className="flex-1">
        <p className="font-medium text-sm">{app.app_name}</p>
        <p className="text-xs text-gray-500">{app.unique_action_types} action types</p>
      </div>
      <div className="flex items-center space-x-4">
        <span className="text-sm">{app.total_actions} actions</span>
        <div className="w-20">
          <div className="flex items-center">
            <div className="w-12 bg-gray-200 rounded-full h-1.5 mr-2">
              <div
                className={`h-1.5 rounded-full ${
                  app.success_rate >= 90
                    ? 'bg-green-500'
                    : app.success_rate >= 70
                    ? 'bg-yellow-500'
                    : 'bg-red-500'
                }`}
                style={{ width: `${app.success_rate}%` }}
              />
            </div>
            <span className="text-xs">{app.success_rate.toFixed(0)}%</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function FailureRow({ run }: { run: PlaybookRun }) {
  return (
    <div className="flex items-center justify-between py-2 px-3 bg-red-50 rounded">
      <div>
        <p className="font-medium text-sm">{run.playbook_name || 'Unknown Playbook'}</p>
        <p className="text-xs text-gray-500">
          {run.event_time
            ? new Date(run.event_time).toLocaleString()
            : 'Unknown time'}
        </p>
      </div>
      <div className="text-right">
        <span className="px-2 py-1 text-xs bg-red-100 text-red-800 rounded">
          {run.status}
        </span>
        {run.duration_seconds && (
          <p className="text-xs text-gray-500 mt-1">
            {run.duration_seconds.toFixed(1)}s
          </p>
        )}
      </div>
    </div>
  );
}
