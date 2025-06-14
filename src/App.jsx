import React, { useState, useEffect, createContext, useContext } from 'react';
import { User, Lock, Mail, Shield, Users, Settings, Home, LogOut, Eye, EyeOff, Menu, X } from 'lucide-react';

// Auth Context
const AuthContext = createContext();

// API Configuration
// const API_BASE_URL = 'https://auth-backend-5azn.onrender.com';

const API_BASE_URL = 'http://localhost:5000';



// API calls
const api = {
  login: async (email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });
    
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Login failed');
    }
    return data;
  },
  
  register: async (name, email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ name, email, password }),
    });
    
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Registration failed');
    }
    return data;
  },
  
  logout: async (token) => {
    const response = await fetch(`${API_BASE_URL}/auth/logout`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });
    return response.json();
  },
  
  getUsers: async (token) => {
    const response = await fetch(`${API_BASE_URL}/users`, {
      headers: {
        'Authorization': `Bearer ${token}`,
      },
    });
    
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || 'Failed to fetch users');
    }
    return data;
  }
};

// Auth Provider Component
const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [token, setToken] = useState(null);

  useEffect(() => {
    // Check for existing session
    const storedToken = localStorage.getItem('token');
    const userData = localStorage.getItem('user');
    
    if (storedToken && userData) {
      setToken(storedToken);
      setUser(JSON.parse(userData));
      setIsAuthenticated(true);
    }
    setLoading(false);
  }, []);

  const login = async (email, password) => {
    try {
      const response = await api.login(email, password);
      if (response.success) {
        setUser(response.user);
        setToken(response.token);
        setIsAuthenticated(true);
        localStorage.setItem('token', response.token);
        localStorage.setItem('user', JSON.stringify(response.user));
        return { success: true };
      }
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const register = async (name, email, password) => {
    try {
      const response = await api.register(name, email, password);
      return { success: true };
    } catch (error) {
      return { success: false, error: error.message };
    }
  };

  const logout = async () => {
    try {
      if (token) {
        await api.logout(token);
      }
      setUser(null);
      setToken(null);
      setIsAuthenticated(false);
      localStorage.removeItem('token');
      localStorage.removeItem('user');
    } catch (error) {
      console.error('Logout error:', error);
    }
  };

  const hasRole = (role) => {
    return user?.role === role;
  };

  const hasAnyRole = (roles) => {
    return roles.includes(user?.role);
  };

  return (
    <AuthContext.Provider value={{
      user,
      token,
      isAuthenticated,
      loading,
      login,
      register,
      logout,
      hasRole,
      hasAnyRole
    }}>
      {children}
    </AuthContext.Provider>
  );
};

// Hook to use auth context
const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};

// Protected Route Component
const ProtectedRoute = ({ children, roles = [] }) => {
  const { isAuthenticated, user, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <LoginForm />;
  }

  if (roles.length > 0 && !roles.includes(user?.role)) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50 px-4">
        <div className="text-center max-w-md">
          <Shield className="mx-auto h-12 w-12 text-red-400" />
          <h2 className="mt-2 text-lg font-medium text-gray-900">Access Denied</h2>
          <p className="mt-1 text-sm text-gray-500">You don't have permission to access this page.</p>
        </div>
      </div>
    );
  }

  return children;
};

// Login Form Component
const LoginForm = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [isRegister, setIsRegister] = useState(false);
  const [name, setName] = useState('');
  const { login, register } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      let result;
      if (isRegister) {
        result = await register(name, email, password);
        if (result.success) {
          setIsRegister(false);
          setName('');
          setEmail('');
          setPassword('');
          alert('Registration successful! Please login.');
        }
      } else {
        result = await login(email, password);
      }

      if (!result.success) {
        setError(result.error);
      }
    } catch (error) {
      setError('An unexpected error occurred');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 py-8 px-4 sm:px-6 lg:px-8">
      <div className="max-w-md w-full space-y-8">
        <div>
          <div className="flex justify-center">
            <Shield className="h-12 w-12 text-blue-600" />
          </div>
          <h2 className="mt-6 text-center text-2xl sm:text-3xl font-extrabold text-gray-900">
            {isRegister ? 'Create your account' : 'Sign in to your account'}
          </h2>
          <p className="mt-2 text-center text-xs sm:text-sm text-gray-600 px-2">
            Demo: admin@example.com / user@example.com / moderator@example.com (password: password123)
          </p>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="space-y-4">
            {isRegister && (
              <div>
                <label htmlFor="name" className="block text-sm font-medium text-gray-700">
                  Full Name
                </label>
                <div className="mt-1 relative">
                  <User className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                  <input
                    id="name"
                    name="name"
                    type="text"
                    required={isRegister}
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="pl-10 block w-full rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-blue-500 text-sm sm:text-base"
                    placeholder="Enter your full name"
                  />
                </div>
              </div>
            )}
            
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700">
                Email Address
              </label>
              <div className="mt-1 relative">
                <Mail className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <input
                  id="email"
                  name="email"
                  type="email"
                  required
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="pl-10 block w-full rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-blue-500 text-sm sm:text-base"
                  placeholder="Enter your email"
                />
              </div>
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700">
                Password
              </label>
              <div className="mt-1 relative">
                <Lock className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <input
                  id="password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="pl-10 pr-10 block w-full rounded-md border border-gray-300 px-3 py-2 placeholder-gray-400 shadow-sm focus:border-blue-500 focus:outline-none focus:ring-blue-500 text-sm sm:text-base"
                  placeholder="Enter your password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-gray-400 hover:text-gray-600"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>
          </div>

          {error && (
            <div className="text-red-600 text-sm text-center bg-red-50 p-3 rounded-md">
              {error}
            </div>
          )}

          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white"></div>
              ) : (
                isRegister ? 'Register' : 'Sign In'
              )}
            </button>
          </div>

          <div className="text-center">
            <button
              type="button"
              onClick={() => {
                setIsRegister(!isRegister);
                setError('');
              }}
              className="text-blue-600 hover:text-blue-500 text-sm"
            >
              {isRegister ? 'Already have an account? Sign in' : "Don't have an account? Register"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

// Dashboard Component
const Dashboard = () => {
  const { user, logout, hasRole, hasAnyRole, token } = useAuth();
  const [activeTab, setActiveTab] = useState('dashboard');
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [users, setUsers] = useState([]);
  const [loadingUsers, setLoadingUsers] = useState(false);

  const handleLogout = async () => {
    await logout();
  };

  const loadUsers = async () => {
    if (!hasAnyRole(['admin', 'moderator'])) return;
    
    setLoadingUsers(true);
    try {
      const response = await api.getUsers(token);
      setUsers(response.users);
    } catch (error) {
      console.error('Failed to load users:', error);
    } finally {
      setLoadingUsers(false);
    }
  };

  useEffect(() => {
    if (activeTab === 'users') {
      loadUsers();
    }
  }, [activeTab]);

  const navigation = [
    { name: 'Dashboard', id: 'dashboard', icon: Home, roles: ['admin', 'user', 'moderator'] },
    { name: 'Users', id: 'users', icon: Users, roles: ['admin', 'moderator'] },
    { name: 'Settings', id: 'settings', icon: Settings, roles: ['admin'] },
  ];

  const filteredNavigation = navigation.filter(item => 
    item.roles.some(role => hasAnyRole([role]))
  );

  const Sidebar = ({ mobile = false }) => (
    <nav className={`space-y-2 ${mobile ? 'px-4 py-4' : ''}`}>
      {filteredNavigation.map((item) => {
        const Icon = item.icon;
        return (
          <button
            key={item.id}
            onClick={() => {
              setActiveTab(item.id);
              if (mobile) setSidebarOpen(false);
            }}
            className={`w-full flex items-center space-x-3 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === item.id
                ? 'bg-blue-100 text-blue-700'
                : 'text-gray-600 hover:text-gray-900 hover:bg-gray-50'
            }`}
          >
            <Icon className="h-5 w-5 flex-shrink-0" />
            <span>{item.name}</span>
          </button>
        );
      })}
    </nav>
  );

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="fixed inset-0 bg-gray-600 bg-opacity-75" onClick={() => setSidebarOpen(false)}></div>
          <div className="relative flex-1 flex flex-col max-w-xs w-full bg-white">
            <div className="absolute top-0 right-0 -mr-12 pt-2">
              <button
                onClick={() => setSidebarOpen(false)}
                className="ml-1 flex items-center justify-center h-10 w-10 rounded-full focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white"
              >
                <X className="h-6 w-6 text-white" />
              </button>
            </div>
            <div className="flex-1 h-0 pt-5 pb-4 overflow-y-auto">
              <div className="flex-shrink-0 flex items-center px-4">
                <Shield className="h-8 w-8 text-blue-600 mr-3" />
                <h1 className="text-xl font-bold text-gray-900">MERN Auth</h1>
              </div>
              <div className="mt-5">
                <Sidebar mobile={true} />
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center">
              <button
                onClick={() => setSidebarOpen(true)}
                className="lg:hidden mr-2 p-2 rounded-md text-gray-400 hover:text-gray-500 hover:bg-gray-100"
              >
                <Menu className="h-6 w-6" />
              </button>
              <Shield className="h-8 w-8 text-blue-600 mr-3" />
              <h1 className="text-xl sm:text-2xl font-bold text-gray-900 hidden sm:block">MERN Auth System</h1>
              <h1 className="text-lg font-bold text-gray-900 sm:hidden">MERN Auth</h1>
            </div>
            <div className="flex items-center space-x-2 sm:space-x-4">
              <div className="flex items-center space-x-2">
                <div className="text-sm text-right">
                  <p className="text-gray-900 font-medium truncate max-w-24 sm:max-w-none">{user?.name}</p>
                  <p className="text-gray-500 capitalize text-xs sm:text-sm">{user?.role}</p>
                </div>
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center space-x-1 text-gray-500 hover:text-gray-700 px-2 sm:px-3 py-2 rounded-md text-sm font-medium"
              >
                <LogOut className="h-4 w-4" />
                <span className="hidden sm:inline">Logout</span>
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 sm:py-8">
        <div className="flex flex-col lg:flex-row lg:space-x-8 space-y-6 lg:space-y-0">
          {/* Desktop Sidebar */}
          <div className="hidden lg:block w-64 flex-shrink-0">
            <div className="bg-white rounded-lg shadow p-4">
              <Sidebar />
            </div>
          </div>

          {/* Main Content */}
          <div className="flex-1">
            <div className="bg-white rounded-lg shadow p-4 sm:p-6">
              {activeTab === 'dashboard' && (
                <div>
                  <h2 className="text-xl sm:text-2xl font-bold text-gray-900 mb-6">Dashboard</h2>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-6">
                    <div className="bg-blue-50 p-4 sm:p-6 rounded-lg">
                      <h3 className="text-lg font-semibold text-blue-900">Welcome!</h3>
                      <p className="text-blue-700 mt-2 text-sm sm:text-base">You are logged in as {user?.role}</p>
                    </div>
                    <div className="bg-green-50 p-4 sm:p-6 rounded-lg">
                      <h3 className="text-lg font-semibold text-green-900">Session Active</h3>
                      <p className="text-green-700 mt-2 text-sm sm:text-base">JWT-based session management</p>
                    </div>
                    <div className="bg-purple-50 p-4 sm:p-6 rounded-lg sm:col-span-2 lg:col-span-1">
                      <h3 className="text-lg font-semibold text-purple-900">Role-Based Access</h3>
                      <p className="text-purple-700 mt-2 text-sm sm:text-base">Protected routes working</p>
                    </div>
                  </div>

                  <div className="mt-8">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">Your Permissions</h3>
                    <div className="space-y-2">
                      <div className="flex items-center space-x-2">
                        <div className="w-2 h-2 bg-green-500 rounded-full flex-shrink-0"></div>
                        <span className="text-sm sm:text-base">Access Dashboard</span>
                      </div>
                      {hasAnyRole(['admin', 'moderator']) && (
                        <div className="flex items-center space-x-2">
                          <div className="w-2 h-2 bg-green-500 rounded-full flex-shrink-0"></div>
                          <span className="text-sm sm:text-base">Manage Users</span>
                        </div>
                      )}
                      {hasRole('admin') && (
                        <div className="flex items-center space-x-2">
                          <div className="w-2 h-2 bg-green-500 rounded-full flex-shrink-0"></div>
                          <span className="text-sm sm:text-base">System Settings</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'users' && hasAnyRole(['admin', 'moderator']) && (
                <div>
                  <h2 className="text-xl sm:text-2xl font-bold text-gray-900 mb-6">User Management</h2>
                  {loadingUsers ? (
                    <div className="flex justify-center py-8">
                      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {users.length === 0 ? (
                        <div className="text-center py-8 text-gray-500">
                          <Users className="mx-auto h-12 w-12 text-gray-300 mb-4" />
                          <p>No users found</p>
                        </div>
                      ) : (
                        users.map((user, index) => (
                          <div key={user._id || index} className="flex flex-col sm:flex-row sm:items-center justify-between p-4 border rounded-lg space-y-3 sm:space-y-0">
                            <div className="flex-1">
                              <h4 className="font-medium text-gray-900 text-sm sm:text-base">{user.name}</h4>
                              <p className="text-xs sm:text-sm text-gray-500 break-all">{user.email}</p>
                              <p className="text-xs text-gray-400 mt-1">
                                Created: {new Date(user.createdAt).toLocaleDateString()}
                              </p>
                            </div>
                            <div className="flex items-center justify-between sm:justify-end space-x-4">
                              <span className={`px-2 py-1 rounded-full text-xs font-medium ${
                                user.role === 'admin' ? 'bg-red-100 text-red-800' :
                                user.role === 'moderator' ? 'bg-yellow-100 text-yellow-800' :
                                'bg-green-100 text-green-800'
                              }`}>
                                {user.role}
                              </span>
                              <span className="px-2 py-1 rounded-full text-xs font-medium bg-green-100 text-green-800">
                                Active
                              </span>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  )}
                </div>
              )}

              {activeTab === 'settings' && hasRole('admin') && (
                <div>
                  <h2 className="text-xl sm:text-2xl font-bold text-gray-900 mb-6">System Settings</h2>
                  <div className="space-y-6">
                    <div className="border rounded-lg p-4 sm:p-6">
                      <h3 className="text-lg font-medium text-gray-900 mb-4">Authentication Settings</h3>
                      <div className="space-y-4">
                        <label className="flex items-start sm:items-center space-x-3">
                          <input type="checkbox" className="rounded border-gray-300 mt-1 sm:mt-0 flex-shrink-0" defaultChecked />
                          <span className="text-sm text-gray-700">Enable JWT session management</span>
                        </label>
                        <label className="flex items-start sm:items-center space-x-3">
                          <input type="checkbox" className="rounded border-gray-300 mt-1 sm:mt-0 flex-shrink-0" defaultChecked />
                          <span className="text-sm text-gray-700">Require email verification</span>
                        </label>
                        <label className="flex items-start sm:items-center space-x-3">
                          <input type="checkbox" className="rounded border-gray-300 mt-1 sm:mt-0 flex-shrink-0" />
                          <span className="text-sm text-gray-700">Enable two-factor authentication</span>
                        </label>
                      </div>
                    </div>
                    <div className="border rounded-lg p-4 sm:p-6">
                      <h3 className="text-lg font-medium text-gray-900 mb-2">Role Management</h3>
                      <p className="text-sm text-gray-600 mb-4">Configure role-based access control and permissions.</p>
                      <button className="w-full sm:w-auto px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors">
                        Manage Roles
                      </button>
                    </div>
                    <div className="border rounded-lg p-4 sm:p-6">
                      <h3 className="text-lg font-medium text-gray-900 mb-2">Security Settings</h3>
                      <p className="text-sm text-gray-600 mb-4">Configure security policies and access controls.</p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <button className="px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors">
                          Password Policy
                        </button>
                        <button className="px-4 py-2 border border-gray-300 text-gray-700 rounded-md hover:bg-gray-50 transition-colors">
                          Session Management
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

// Main App Component


const App = () => {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-100">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
          <p className="mt-4 text-gray-600">Loading...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="App">
      {isAuthenticated ? <Dashboard /> :        <LoginForm />}
    </div>
  );
};


// Root component with AuthProvider
export default function MERNAuthSystem() {
  return (
    <AuthProvider>
      <App />
    </AuthProvider>
  );
}