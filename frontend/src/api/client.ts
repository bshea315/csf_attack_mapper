import axios from 'axios';
import type {
  AuthToken,
  LoginRequest,
  User,
  Detection,
  DetectionListResponse,
  MitreTechnique,
  CsfCategory,
  OverviewStats,
  AttackCoverageResponse,
  CsfCoverageResponse,
  GapAnalysisResponse,
  RecommendationResponse,
  IngestBatch,
} from '../types';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token to requests
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 responses
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// Auth
export const authApi = {
  login: async (credentials: LoginRequest): Promise<AuthToken> => {
    const { data } = await api.post('/auth/login', credentials);
    return data;
  },
  logout: async (): Promise<void> => {
    await api.post('/auth/logout');
  },
  me: async (): Promise<User> => {
    const { data } = await api.get('/auth/me');
    return data;
  },
};

// Detections
export const detectionsApi = {
  list: async (params: {
    page?: number;
    page_size?: number;
    search?: string;
    severity?: string;
    status?: string;
  }): Promise<DetectionListResponse> => {
    const { data } = await api.get('/detections', { params });
    return data;
  },
  get: async (id: number): Promise<Detection> => {
    const { data } = await api.get(`/detections/${id}`);
    return data;
  },
  update: async (id: number, updates: Partial<Detection>): Promise<Detection> => {
    const { data } = await api.put(`/detections/${id}`, updates);
    return data;
  },
  recompute: async (id: number): Promise<Detection> => {
    const { data } = await api.post(`/detections/${id}/recompute`);
    return data;
  },
  delete: async (id: number): Promise<void> => {
    await api.delete(`/detections/${id}`);
  },
};

// Mappings
export const mappingsApi = {
  listMitreTechniques: async (params?: {
    tactic?: string;
    search?: string;
  }): Promise<MitreTechnique[]> => {
    const { data } = await api.get('/mappings/mitre/techniques', { params });
    return data;
  },
  listCsfCategories: async (params?: {
    function?: string;
  }): Promise<CsfCategory[]> => {
    const { data } = await api.get('/mappings/csf/categories', { params });
    return data;
  },
  updateDetectionMitre: async (
    detectionId: number,
    mappingId: number,
    updates: { confidence?: number; rationale?: string; is_accepted?: boolean }
  ): Promise<void> => {
    await api.put(`/mappings/detections/${detectionId}/mitre/${mappingId}`, updates);
  },
  addDetectionMitre: async (
    detectionId: number,
    mapping: { technique_id: string; confidence: number; rationale: string }
  ): Promise<void> => {
    await api.post(`/mappings/detections/${detectionId}/mitre`, mapping);
  },
};

// Analytics
export const analyticsApi = {
  getOverview: async (): Promise<OverviewStats> => {
    const { data } = await api.get('/analytics/overview');
    return data;
  },
  getAttackCoverage: async (): Promise<AttackCoverageResponse> => {
    const { data } = await api.get('/analytics/attack-coverage');
    return data;
  },
  getCsfCoverage: async (): Promise<CsfCoverageResponse> => {
    const { data } = await api.get('/analytics/csf-coverage');
    return data;
  },
  getGaps: async (): Promise<GapAnalysisResponse> => {
    const { data } = await api.get('/analytics/gaps');
    return data;
  },
  getRecommendations: async (): Promise<RecommendationResponse> => {
    const { data } = await api.get('/analytics/recommendations');
    return data;
  },
  getTechniqueDetails: async (techniqueId: string): Promise<{
    technique_id: string;
    technique_name: string;
    description: string | null;
    tactics: string[];
    is_subtechnique: boolean;
    parent_technique_id: string | null;
    url: string;
    detection_count: number;
    detections: Array<{
      id: number;
      detection_id: string;
      name: string;
      severity: string;
      status: string;
      confidence: number;
      method: string;
      rationale: string;
    }>;
    subtechniques: Array<{
      technique_id: string;
      technique_name: string;
      detection_count: number;
      url: string;
    }>;
  }> => {
    const { data } = await api.get(`/analytics/technique/${techniqueId}`);
    return data;
  },
};

// Ingest
export const ingestApi = {
  uploadCsv: async (file: File): Promise<IngestBatch> => {
    const formData = new FormData();
    formData.append('file', file);
    const { data } = await api.post('/ingest/csv', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return data;
  },
  uploadYaml: async (file: File): Promise<IngestBatch> => {
    const formData = new FormData();
    formData.append('file', file);
    const { data } = await api.post('/ingest/yaml', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return data;
  },
  paste: async (content: string): Promise<IngestBatch> => {
    const { data } = await api.post('/ingest/paste', { content });
    return data;
  },
  getBatches: async (): Promise<IngestBatch[]> => {
    const { data } = await api.get('/ingest/batches');
    return data;
  },
};

// Exports
export const exportsApi = {
  getDetectionsCsv: () => `/api/exports/detections.csv`,
  getAttackCoverageCsv: () => `/api/exports/attack-coverage.csv`,
  getCsfPostureCsv: () => `/api/exports/csf-posture.csv`,
  getFullReportJson: () => `/api/exports/full-report.json`,
};

export default api;
