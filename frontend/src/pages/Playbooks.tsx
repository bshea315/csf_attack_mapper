import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { playbooksApi } from '../api/client';
import type { Playbook } from '../types';

export default function Playbooks() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [filterActive, setFilterActive] = useState<boolean | undefined>(undefined);
  const pageSize = 20;

  const { data, isLoading, error } = useQuery({
    queryKey: ['playbooks', page, search, filterActive],
    queryFn: () => playbooksApi.list({
      page,
      page_size: pageSize,
      search: search || undefined,
      is_active: filterActive,
    }),
  });

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setPage(1);
  };

  return (
    <div className="max-w-6xl mx-auto p-6">
      <div className="flex justify-between items-center mb-6">
        <h1 className="text-2xl font-bold">SOAR Playbooks</h1>
        <Link
          to="/soar-dashboard"
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
        >
          View Dashboard
        </Link>
      </div>

      {/* Filters */}
      <div className="bg-white rounded-lg shadow mb-6 p-4">
        <form onSubmit={handleSearch} className="flex items-center space-x-4">
          <div className="flex-1">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search playbooks..."
              className="w-full px-3 py-2 border rounded"
            />
          </div>
          <div>
            <select
              value={filterActive === undefined ? '' : filterActive.toString()}
              onChange={(e) => {
                const val = e.target.value;
                setFilterActive(val === '' ? undefined : val === 'true');
                setPage(1);
              }}
              className="px-3 py-2 border rounded"
            >
              <option value="">All Status</option>
              <option value="true">Active</option>
              <option value="false">Inactive</option>
            </select>
          </div>
          <button
            type="submit"
            className="px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
          >
            Search
          </button>
        </form>
      </div>

      {/* Loading/Error States */}
      {isLoading && (
        <div className="text-center py-8 text-gray-500">Loading playbooks...</div>
      )}

      {error && (
        <div className="bg-red-50 text-red-600 p-4 rounded mb-4">
          Error loading playbooks: {(error as Error).message}
        </div>
      )}

      {/* Playbooks Table */}
      {data && (
        <>
          <div className="bg-white rounded-lg shadow overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Playbook
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Category
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Runs
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Success Rate
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Time Saved
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                    Detections
                  </th>
                </tr>
              </thead>
              <tbody className="bg-white divide-y divide-gray-200">
                {data.items.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-6 py-8 text-center text-gray-500">
                      No playbooks found. Sync SOAR logs from the Admin page to import playbooks.
                    </td>
                  </tr>
                ) : (
                  data.items.map((playbook) => (
                    <PlaybookRow key={playbook.id} playbook={playbook} />
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {data.pages > 1 && (
            <div className="flex justify-center items-center space-x-4 mt-6">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="px-3 py-1 border rounded disabled:opacity-50"
              >
                Previous
              </button>
              <span className="text-sm text-gray-600">
                Page {page} of {data.pages} ({data.total} playbooks)
              </span>
              <button
                onClick={() => setPage((p) => Math.min(data.pages, p + 1))}
                disabled={page === data.pages}
                className="px-3 py-1 border rounded disabled:opacity-50"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function PlaybookRow({ playbook }: { playbook: Playbook }) {
  return (
    <tr className="hover:bg-gray-50">
      <td className="px-6 py-4">
        <div className="flex items-center space-x-2">
          <Link
            to={`/playbooks/${playbook.id}`}
            className="text-blue-600 hover:underline font-medium"
          >
            {playbook.name}
          </Link>
          <span
            className={`px-2 py-0.5 text-xs rounded-full ${
              playbook.is_active
                ? 'bg-green-100 text-green-800'
                : 'bg-gray-100 text-gray-800'
            }`}
          >
            {playbook.is_active ? 'Active' : 'Inactive'}
          </span>
        </div>
        {playbook.description && (
          <p className="text-sm text-gray-500 truncate max-w-md">
            {playbook.description}
          </p>
        )}
      </td>
      <td className="px-6 py-4">
        {playbook.category ? (
          <span className="px-2 py-1 text-xs rounded bg-blue-100 text-blue-800">
            {playbook.category}
          </span>
        ) : (
          <span className="text-gray-400">-</span>
        )}
      </td>
      <td className="px-6 py-4 text-sm">
        {playbook.run_count}
      </td>
      <td className="px-6 py-4">
        {playbook.success_rate !== null ? (
          <div className="flex items-center">
            <div className="w-16 bg-gray-200 rounded-full h-2 mr-2">
              <div
                className={`h-2 rounded-full ${
                  playbook.success_rate >= 90
                    ? 'bg-green-500'
                    : playbook.success_rate >= 70
                    ? 'bg-yellow-500'
                    : 'bg-red-500'
                }`}
                style={{ width: `${playbook.success_rate}%` }}
              />
            </div>
            <span className="text-sm">{playbook.success_rate.toFixed(1)}%</span>
          </div>
        ) : (
          <span className="text-gray-400">-</span>
        )}
      </td>
      <td className="px-6 py-4">
        <div className="text-sm">
          <span className="font-medium text-purple-600">
            {playbook.total_time_saved_hours.toFixed(1)}h
          </span>
          {playbook.time_saved_minutes > 0 && (
            <span className="text-gray-400 text-xs block">
              ({playbook.time_saved_minutes}m/run)
            </span>
          )}
        </div>
      </td>
      <td className="px-6 py-4 text-sm">
        {playbook.linked_detection_count > 0 ? (
          <span className="px-2 py-1 text-xs rounded bg-green-100 text-green-800">
            {playbook.linked_detection_count} linked
          </span>
        ) : (
          <span className="text-gray-400">0</span>
        )}
      </td>
    </tr>
  );
}
