import { Routes, Route, Navigate } from 'react-router-dom';
import { useState, createContext, useContext } from 'react';
import type { User } from './types';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Detections from './pages/Detections';
import DetectionDetail from './pages/DetectionDetail';
import AttackCoverage from './pages/AttackCoverage';
import CsfPosture from './pages/CsfPosture';
import Recommendations from './pages/Recommendations';
import Ingest from './pages/Ingest';

interface AuthContextType {
  user: User | null;
  token: string | null;
  login: (token: string, user: User) => void;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used within AuthProvider');
  return context;
};

function App() {
  const [user, setUser] = useState<User | null>(() => {
    const stored = localStorage.getItem('user');
    return stored ? JSON.parse(stored) : null;
  });
  const [token, setToken] = useState<string | null>(() => {
    return localStorage.getItem('token');
  });

  const login = (newToken: string, newUser: User) => {
    localStorage.setItem('token', newToken);
    localStorage.setItem('user', JSON.stringify(newUser));
    setToken(newToken);
    setUser(newUser);
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setToken(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, token, login, logout }}>
      <Routes>
        <Route path="/login" element={!user ? <Login /> : <Navigate to="/" />} />
        <Route
          path="/*"
          element={
            user ? (
              <Layout>
                <Routes>
                  <Route path="/" element={<Dashboard />} />
                  <Route path="/detections" element={<Detections />} />
                  <Route path="/detections/:id" element={<DetectionDetail />} />
                  <Route path="/attack-coverage" element={<AttackCoverage />} />
                  <Route path="/csf-posture" element={<CsfPosture />} />
                  <Route path="/recommendations" element={<Recommendations />} />
                  <Route path="/ingest" element={<Ingest />} />
                </Routes>
              </Layout>
            ) : (
              <Navigate to="/login" />
            )
          }
        />
      </Routes>
    </AuthContext.Provider>
  );
}

export default App;
