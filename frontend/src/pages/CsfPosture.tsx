import { useQuery } from '@tanstack/react-query';
import { analyticsApi, exportsApi } from '../api/client';
import { Download, Info } from 'lucide-react';
import clsx from 'clsx';
import { useState } from 'react';

// CSF 2.0 Category Descriptions
const CSF_DESCRIPTIONS: Record<string, { description: string; examples: string[] }> = {
  // GOVERN
  'GV.OC': {
    description: 'The circumstances — mission, stakeholder expectations, dependencies, and legal, regulatory, and contractual requirements — surrounding the organization\'s cybersecurity risk management decisions are understood.',
    examples: ['Define cybersecurity mission', 'Identify stakeholder requirements', 'Document regulatory obligations'],
  },
  'GV.RM': {
    description: 'The organization\'s priorities, constraints, risk tolerance and appetite statements, and assumptions are established, communicated, and used to support operational risk decisions.',
    examples: ['Establish risk tolerance', 'Define risk appetite statements', 'Communicate risk priorities'],
  },
  'GV.SC': {
    description: 'Cyber supply chain risk management processes are identified, established, managed, monitored, and improved by organizational stakeholders.',
    examples: ['Assess supplier security', 'Monitor third-party risks', 'Manage vendor relationships'],
  },
  // IDENTIFY
  'ID.AM': {
    description: 'The data, personnel, devices, systems, and facilities that enable the organization to achieve business purposes are identified and managed consistent with their relative importance to organizational objectives and the organization\'s risk strategy.',
    examples: ['Inventory hardware/software', 'Classify data assets', 'Map network resources'],
  },
  'ID.RA': {
    description: 'The cybersecurity risk to the organization, assets, and individuals is understood by the organization.',
    examples: ['Identify threats and vulnerabilities', 'Assess risk likelihood/impact', 'Document risk assessments'],
  },
  // PROTECT
  'PR.AA': {
    description: 'Access to physical and logical assets is limited to authorized users, services, and hardware and managed commensurate with the assessed risk of unauthorized access.',
    examples: ['Implement MFA', 'Manage user accounts', 'Enforce least privilege'],
  },
  'PR.AT': {
    description: 'The organization\'s personnel are provided cybersecurity awareness and training so that they can perform their cybersecurity-related tasks.',
    examples: ['Security awareness training', 'Phishing simulations', 'Role-based training'],
  },
  'PR.DS': {
    description: 'Data are managed consistent with the organization\'s risk strategy to protect the confidentiality, integrity, and availability of information.',
    examples: ['Encrypt sensitive data', 'Implement DLP', 'Secure data in transit/at rest'],
  },
  'PR.PS': {
    description: 'Hardware, software, and services of physical and virtual platforms are managed consistent with the organization\'s risk strategy to protect their confidentiality, integrity, and availability.',
    examples: ['Patch management', 'Configuration hardening', 'Endpoint protection'],
  },
  'PR.IR': {
    description: 'Security architectures are managed with the organization\'s risk strategy to protect asset confidentiality, integrity, and availability, and organizational resilience.',
    examples: ['Network segmentation', 'Backup systems', 'Redundancy planning'],
  },
  // DETECT
  'DE.CM': {
    description: 'Assets are monitored to find anomalies, indicators of compromise, and other potentially adverse events.',
    examples: ['SIEM monitoring', 'Endpoint detection', 'Network traffic analysis'],
  },
  'DE.AE': {
    description: 'Anomalies, indicators of compromise, and other potentially adverse events are analyzed to characterize the events and detect cybersecurity incidents.',
    examples: ['Alert triage', 'Threat hunting', 'Incident correlation'],
  },
  // RESPOND
  'RS.MA': {
    description: 'Responses to detected cybersecurity incidents are managed.',
    examples: ['Incident response plans', 'Communication procedures', 'Escalation protocols'],
  },
  'RS.AN': {
    description: 'Investigations are conducted to ensure effective response and support forensics and recovery activities.',
    examples: ['Forensic analysis', 'Root cause analysis', 'Evidence collection'],
  },
  'RS.CO': {
    description: 'Response activities are coordinated with internal and external stakeholders as required by laws, regulations, or policies.',
    examples: ['Stakeholder notification', 'Regulatory reporting', 'Public communications'],
  },
  'RS.MI': {
    description: 'Activities are performed to prevent expansion of an event and mitigate its effects.',
    examples: ['Contain incidents', 'Eradicate threats', 'Apply mitigations'],
  },
  // RECOVER
  'RC.RP': {
    description: 'Restoration activities are performed to ensure operational availability of systems and services affected by cybersecurity incidents.',
    examples: ['System restoration', 'Data recovery', 'Service resumption'],
  },
  'RC.CO': {
    description: 'Restoration activities are coordinated with internal and external parties.',
    examples: ['Recovery communications', 'Stakeholder updates', 'Lessons learned'],
  },
};

// Tooltip component
function Tooltip({ content, examples }: { content: string; examples: string[] }) {
  const [isVisible, setIsVisible] = useState(false);

  return (
    <div className="relative inline-block">
      <button
        className="text-gray-400 hover:text-gray-600 focus:outline-none"
        onMouseEnter={() => setIsVisible(true)}
        onMouseLeave={() => setIsVisible(false)}
        onFocus={() => setIsVisible(true)}
        onBlur={() => setIsVisible(false)}
        aria-label="More information"
      >
        <Info className="h-4 w-4" />
      </button>
      {isVisible && (
        <div className="absolute z-50 w-72 sm:w-80 p-3 bg-gray-900 text-white text-xs rounded-lg shadow-lg -left-32 sm:-left-36 bottom-full mb-2">
          <div className="relative">
            <p className="mb-2">{content}</p>
            {examples.length > 0 && (
              <div>
                <p className="font-semibold text-gray-300 mb-1">Examples:</p>
                <ul className="list-disc list-inside text-gray-300 space-y-0.5">
                  {examples.map((ex, i) => (
                    <li key={i}>{ex}</li>
                  ))}
                </ul>
              </div>
            )}
            {/* Arrow */}
            <div className="absolute left-1/2 -bottom-2 transform -translate-x-1/2 w-0 h-0 border-l-8 border-r-8 border-t-8 border-transparent border-t-gray-900" />
          </div>
        </div>
      )}
    </div>
  );
}

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
    <div className="space-y-4 sm:space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-gray-900">CSF 2.0 Posture</h1>
          <p className="text-sm sm:text-base text-gray-600">
            Overall coverage score: {(data.overall_score * 100).toFixed(0)}%
          </p>
        </div>
        <a
          href={exportsApi.getCsfPostureCsv()}
          className="flex items-center gap-2 px-3 sm:px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 text-sm self-start sm:self-auto"
        >
          <Download className="h-4 w-4" />
          <span>Export CSV</span>
        </a>
      </div>

      {/* Function Overview */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2 sm:gap-4">
        {data.functions.map((func) => {
          const colors = functionColors[func.function] || { bg: 'bg-gray-500', border: 'border-gray-500' };
          const coveredCats = func.covered_categories ?? func.covered_subcategories ?? 0;
          const totalCats = func.total_categories ?? func.total_subcategories ?? 0;
          return (
            <div
              key={func.function}
              className={clsx('bg-white rounded-lg shadow p-3 sm:p-4 border-t-4', colors.border)}
            >
              <h3 className="text-sm sm:text-base font-semibold text-gray-900">{func.function}</h3>
              <div className="mt-2">
                <div className="flex items-end gap-1">
                  <span className="text-2xl sm:text-3xl font-bold">
                    {(func.average_score * 100).toFixed(0)}
                  </span>
                  <span className="text-gray-500 mb-1">%</span>
                </div>
                <p className="text-xs sm:text-sm text-gray-500">
                  {coveredCats} of {totalCats} categories
                </p>
                <p className="text-xs sm:text-sm text-gray-500">
                  {func.detection_count} detection{func.detection_count !== 1 ? 's' : ''}
                </p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Detailed Categories */}
      <div className="bg-white rounded-lg shadow">
        <div className="px-4 sm:px-6 py-3 sm:py-4 border-b border-gray-200">
          <h2 className="text-base sm:text-lg font-semibold text-gray-900">Category Details</h2>
        </div>
        <div className="divide-y divide-gray-200">
          {data.functions.map((func) => {
            const colors = functionColors[func.function] || { bg: 'bg-gray-500', border: 'border-gray-500' };
            return (
              <div key={func.function} className="p-4 sm:p-6">
                <div className="flex flex-wrap items-center gap-2 sm:gap-3 mb-4">
                  <span className={clsx('px-2 sm:px-3 py-1 text-white text-xs sm:text-sm font-medium rounded', colors.bg)}>
                    {func.function}
                  </span>
                  <span className="text-sm text-gray-500">
                    Average: {(func.average_score * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2 sm:gap-3">
                  {func.categories.map((cat) => {
                    const catInfo = CSF_DESCRIPTIONS[cat.id] || CSF_DESCRIPTIONS[cat.category];
                    return (
                      <div
                        key={cat.id}
                        className="p-2 sm:p-3 bg-gray-50 rounded-lg"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-1.5">
                            <span className="text-sm sm:text-base font-medium text-gray-900">{cat.id}</span>
                            {catInfo && (
                              <Tooltip content={catInfo.description} examples={catInfo.examples} />
                            )}
                          </div>
                          <span className={clsx(
                            'px-2 py-0.5 sm:py-1 text-xs rounded',
                            cat.score > 0.5 ? 'bg-green-100 text-green-800' :
                            cat.score > 0.2 ? 'bg-yellow-100 text-yellow-800' :
                            cat.score > 0 ? 'bg-red-100 text-red-800' :
                            'bg-gray-100 text-gray-800'
                          )}>
                            {(cat.score * 100).toFixed(0)}%
                          </span>
                        </div>
                        <p className="text-xs sm:text-sm text-gray-600 line-clamp-2">{cat.name}</p>
                        <p className="text-xs text-gray-400 mt-1">
                          {cat.detection_count} detection{cat.detection_count !== 1 ? 's' : ''}
                        </p>
                        {/* Progress bar */}
                        <div className="mt-2 h-1.5 sm:h-2 bg-gray-200 rounded-full overflow-hidden">
                          <div
                            className={clsx('h-full rounded-full', colors.bg)}
                            style={{ width: `${cat.score * 100}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
