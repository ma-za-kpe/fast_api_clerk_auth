'use client';

import { useEffect, useState } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { Settings, Users, Database, TrendingUp, Shield, Activity, RefreshCw, Loader2, Plus, Edit2, Trash2, CheckCircle, AlertCircle } from 'lucide-react';

interface ReferenceItem {
  id: number;
  name: string;
  description?: string;
  is_active: boolean;
}

export default function AdminDashboard() {
  const { isLoaded, isSignedIn, user } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [populatingData, setPopulatingData] = useState(false);
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedRefType, setSelectedRefType] = useState<string>('developer-roles');
  const [referenceData, setReferenceData] = useState<ReferenceItem[]>([]);
  const [editingItem, setEditingItem] = useState<ReferenceItem | null>(null);
  const [newItemName, setNewItemName] = useState('');
  const [newItemDescription, setNewItemDescription] = useState('');
  
  const [stats, setStats] = useState({
    totalUsers: 0,
    activeProjects: 0,
    pendingVetting: 0,
    totalRevenue: 0,
    monthlyGrowth: 0,
    activeClients: 0,
    activeDevelopers: 0,
    completionRate: 0,
  });

  const referenceTypes = [
    { id: 'developer-roles', name: 'Developer Roles', endpoint: 'developer-roles' },
    { id: 'tech-stacks', name: 'Tech Stacks', endpoint: 'tech-stacks' },
    { id: 'company-sizes', name: 'Company Sizes', endpoint: 'company-sizes' },
    { id: 'business-types', name: 'Business Types', endpoint: 'business-types' },
    { id: 'project-types', name: 'Project Types', endpoint: 'project-types' },
    { id: 'project-categories', name: 'Project Categories', endpoint: 'project-categories' },
    { id: 'project-scopes', name: 'Project Scopes', endpoint: 'project-scopes' },
    { id: 'experience-levels', name: 'Experience Levels', endpoint: 'experience-levels' },
    { id: 'budget-types', name: 'Budget Types', endpoint: 'budget-types' },
    { id: 'milestone-statuses', name: 'Milestone Statuses', endpoint: 'milestone-statuses' },
    { id: 'task-priorities', name: 'Task Priorities', endpoint: 'task-priorities' },
    { id: 'task-statuses', name: 'Task Statuses', endpoint: 'task-statuses' },
  ];

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      loadDashboardData();
    }
  }, [isLoaded, isSignedIn]);

  useEffect(() => {
    // Only load reference data when actually viewing that tab
    if (activeTab === 'reference' && selectedRefType) {
      const timer = setTimeout(() => {
        loadReferenceData(selectedRefType);
      }, 100); // Small delay to avoid blocking UI
      return () => clearTimeout(timer);
    }
  }, [activeTab, selectedRefType]);

  const loadDashboardData = async () => {
    try {
      // Check admin privileges first (fastest check)
      const isAdmin = user?.publicMetadata?.is_admin === true || user?.privateMetadata?.is_admin === true;
      
      if (!isAdmin) {
        router.push('/dashboard');
        return;
      }

      // Load data in parallel to reduce loading time
      const [analyticsData, usersData] = await Promise.all([
        api.admin.getAnalytics().catch(() => null),
        api.admin.getUsers({ page_size: 1 }).catch(() => null),
      ]);
        
      setStats({
        totalUsers: usersData?.total || 0,
        activeProjects: analyticsData?.active_projects_count || 0,
        pendingVetting: analyticsData?.pending_projects_count || 0,
        totalRevenue: analyticsData?.total_project_value || 0,
        monthlyGrowth: analyticsData?.growth_rate_projects || 0,
        activeClients: analyticsData?.total_companies || 0,
        activeDevelopers: analyticsData?.total_developers || 0,
        completionRate: analyticsData?.completed_projects_count || 0,
      });
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const loadReferenceData = async (type: string) => {
    try {
      const endpoint = referenceTypes.find(t => t.id === type)?.endpoint;
      if (!endpoint) return;

      const data = await api.callApi(`/admin/reference/${endpoint}`);
      setReferenceData(data);
    } catch (error) {
      console.error('Failed to load reference data:', error);
      setReferenceData([]);
    }
  };

  const handlePopulateAllData = async () => {
    if (!confirm('This will populate all reference data tables. Continue?')) return;
    
    setPopulatingData(true);
    try {
      await api.admin.populateReferenceData();
      alert('Reference data populated successfully!');
      loadReferenceData(selectedRefType);
    } catch (error: any) {
      console.error('Failed to populate data:', error);
      alert(error.message || 'Failed to populate reference data');
    } finally {
      setPopulatingData(false);
    }
  };

  const handleAddItem = async () => {
    if (!newItemName.trim()) return;

    try {
      const endpoint = referenceTypes.find(t => t.id === selectedRefType)?.endpoint;
      if (!endpoint) return;

      await api.callApi(`/admin/reference/${endpoint}`, {
        method: 'POST',
        body: JSON.stringify({
          name: newItemName,
          description: newItemDescription,
        }),
      });

      setNewItemName('');
      setNewItemDescription('');
      loadReferenceData(selectedRefType);
    } catch (error: any) {
      console.error('Failed to add item:', error);
      alert(error.message || 'Failed to add item');
    }
  };

  const handleUpdateItem = async (item: ReferenceItem) => {
    try {
      const endpoint = referenceTypes.find(t => t.id === selectedRefType)?.endpoint;
      if (!endpoint) return;

      await api.callApi(`/admin/reference/${endpoint}/${item.id}`, {
        method: 'PUT',
        body: JSON.stringify({
          name: item.name,
          description: item.description,
          is_active: item.is_active,
        }),
      });

      setEditingItem(null);
      loadReferenceData(selectedRefType);
    } catch (error: any) {
      console.error('Failed to update item:', error);
      alert(error.message || 'Failed to update item');
    }
  };

  const handleDeleteItem = async (id: number) => {
    if (!confirm('Are you sure you want to delete this item?')) return;

    try {
      const endpoint = referenceTypes.find(t => t.id === selectedRefType)?.endpoint;
      if (!endpoint) return;

      await api.callApi(`/admin/reference/${endpoint}/${id}`, {
        method: 'DELETE',
      });

      loadReferenceData(selectedRefType);
    } catch (error: any) {
      console.error('Failed to delete item:', error);
      alert(error.message || 'Failed to delete item');
    }
  };

  if (!isLoaded) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
        <Loader2 className="w-8 h-8 text-white animate-spin" />
      </div>
    );
  }

  if (!isSignedIn) {
    router.push('/sign-in');
    return null;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
      {/* Navigation */}
      <nav className="bg-black/20 backdrop-blur-xl border-b border-white/10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-8">
              <div className="flex items-center gap-2">
                <Settings className="w-8 h-8 text-red-400" />
                <span className="text-xl font-bold text-white">Admin Panel</span>
              </div>
              <div className="flex gap-6">
                <button
                  onClick={() => setActiveTab('overview')}
                  className={`${activeTab === 'overview' ? 'text-white' : 'text-gray-300 hover:text-white'} font-medium`}
                >
                  Overview
                </button>
                <button
                  onClick={() => setActiveTab('users')}
                  className={`${activeTab === 'users' ? 'text-white' : 'text-gray-300 hover:text-white'} font-medium`}
                >
                  Users
                </button>
                <button
                  onClick={() => setActiveTab('reference')}
                  className={`${activeTab === 'reference' ? 'text-white' : 'text-gray-300 hover:text-white'} font-medium`}
                >
                  Reference Data
                </button>
                <button
                  onClick={() => setActiveTab('analytics')}
                  className={`${activeTab === 'analytics' ? 'text-white' : 'text-gray-300 hover:text-white'} font-medium`}
                >
                  Analytics
                </button>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-sm text-gray-300">
                {user?.firstName} {user?.lastName}
              </span>
              <button
                onClick={() => signOut()}
                className="px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white text-sm transition-colors"
              >
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {activeTab === 'overview' && (
          <>
            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
              {loading ? (
                // Loading skeleton
                Array(4).fill(0).map((_, i) => (
                  <div key={i} className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                    <div className="w-12 h-12 bg-gray-500/20 rounded-lg mb-4 animate-pulse"></div>
                    <div className="h-8 bg-gray-500/20 rounded mb-2 animate-pulse"></div>
                    <div className="h-4 bg-gray-500/20 rounded w-2/3 animate-pulse"></div>
                  </div>
                ))
              ) : (
                // Actual stats
                <>
                  <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                    <div className="flex items-center justify-between mb-4">
                      <div className="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                        <Users className="w-6 h-6 text-blue-400" />
                      </div>
                    </div>
                    <p className="text-2xl font-bold text-white">{stats.totalUsers}</p>
                    <p className="text-gray-400 text-sm">Total Users</p>
                  </div>

                  <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                    <div className="flex items-center justify-between mb-4">
                      <div className="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                        <Activity className="w-6 h-6 text-green-400" />
                      </div>
                    </div>
                    <p className="text-2xl font-bold text-white">{stats.activeProjects}</p>
                    <p className="text-gray-400 text-sm">Active Projects</p>
                  </div>

                  <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                    <div className="flex items-center justify-between mb-4">
                      <div className="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
                        <TrendingUp className="w-6 h-6 text-purple-400" />
                      </div>
                    </div>
                    <p className="text-2xl font-bold text-white">${(stats.totalRevenue / 1000).toFixed(0)}k</p>
                    <p className="text-gray-400 text-sm">Total Revenue</p>
                  </div>

                  <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                    <div className="flex items-center justify-between mb-4">
                      <div className="w-12 h-12 bg-orange-500/20 rounded-lg flex items-center justify-center">
                        <Shield className="w-6 h-6 text-orange-400" />
                      </div>
                    </div>
                    <p className="text-2xl font-bold text-white">{stats.completionRate}%</p>
                    <p className="text-gray-400 text-sm">Completion Rate</p>
                  </div>
                </>
              )}
            </div>

            {/* Additional Stats */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">User Distribution</h3>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Active Clients</span>
                    <span className="text-white font-medium">{stats.activeClients}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Active Developers</span>
                    <span className="text-white font-medium">{stats.activeDevelopers}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">Pending Vetting</span>
                    <span className="text-yellow-400 font-medium">{stats.pendingVetting}</span>
                  </div>
                </div>
              </div>

              <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Growth Metrics</h3>
                <div className="space-y-3">
                  <div className="flex justify-between">
                    <span className="text-gray-400">Monthly Growth</span>
                    <span className="text-green-400 font-medium">+{stats.monthlyGrowth}%</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">New Users (30d)</span>
                    <span className="text-white font-medium">0</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-gray-400">New Projects (30d)</span>
                    <span className="text-white font-medium">0</span>
                  </div>
                </div>
              </div>

              <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
                <div className="space-y-3">
                  <button
                    onClick={handlePopulateAllData}
                    disabled={populatingData}
                    className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-800 text-white font-medium rounded-lg transition-colors"
                  >
                    {populatingData ? (
                      <Loader2 className="w-4 h-4 animate-spin" />
                    ) : (
                      <Database className="w-4 h-4" />
                    )}
                    {populatingData ? 'Populating...' : 'Populate Reference Data'}
                  </button>
                  <button className="w-full px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white font-medium transition-colors">
                    Export Analytics
                  </button>
                  <button className="w-full px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white font-medium transition-colors">
                    View Audit Logs
                  </button>
                </div>
              </div>
            </div>
          </>
        )}

        {activeTab === 'reference' && (
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-8">
            {/* Reference Type Selector */}
            <div className="lg:col-span-1">
              <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                <h3 className="text-lg font-semibold text-white mb-4">Reference Tables</h3>
                <div className="space-y-2">
                  {referenceTypes.map((type) => (
                    <button
                      key={type.id}
                      onClick={() => setSelectedRefType(type.id)}
                      className={`w-full text-left px-3 py-2 rounded-lg transition-all ${
                        selectedRefType === type.id
                          ? 'bg-purple-500/20 border border-purple-500/40 text-purple-300'
                          : 'bg-white/5 hover:bg-white/10 text-gray-400'
                      }`}
                    >
                      {type.name}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Reference Data Management */}
            <div className="lg:col-span-3">
              <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                <div className="flex items-center justify-between mb-6">
                  <h3 className="text-lg font-semibold text-white">
                    {referenceTypes.find(t => t.id === selectedRefType)?.name}
                  </h3>
                  <button
                    onClick={() => loadReferenceData(selectedRefType)}
                    className="inline-flex items-center gap-2 px-3 py-1 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white text-sm transition-colors"
                  >
                    <RefreshCw className="w-3 h-3" />
                    Refresh
                  </button>
                </div>

                {/* Add New Item */}
                <div className="flex gap-3 mb-6">
                  <input
                    type="text"
                    placeholder="Name"
                    value={newItemName}
                    onChange={(e) => setNewItemName(e.target.value)}
                    className="flex-1 px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                  />
                  <input
                    type="text"
                    placeholder="Description (optional)"
                    value={newItemDescription}
                    onChange={(e) => setNewItemDescription(e.target.value)}
                    className="flex-1 px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                  />
                  <button
                    onClick={handleAddItem}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 text-white font-medium rounded-lg transition-colors"
                  >
                    <Plus className="w-4 h-4" />
                    Add
                  </button>
                </div>

                {/* Reference Items List */}
                <div className="space-y-2 max-h-96 overflow-y-auto">
                  {referenceData.map((item) => (
                    <div
                      key={item.id}
                      className="flex items-center gap-3 p-3 bg-white/5 border border-white/10 rounded-lg"
                    >
                      {editingItem?.id === item.id ? (
                        <>
                          <input
                            type="text"
                            value={editingItem.name}
                            onChange={(e) => setEditingItem({ ...editingItem, name: e.target.value })}
                            className="flex-1 px-2 py-1 bg-white/10 border border-white/20 rounded text-white text-sm"
                          />
                          <input
                            type="text"
                            value={editingItem.description || ''}
                            onChange={(e) => setEditingItem({ ...editingItem, description: e.target.value })}
                            className="flex-1 px-2 py-1 bg-white/10 border border-white/20 rounded text-white text-sm"
                          />
                          <button
                            onClick={() => handleUpdateItem(editingItem)}
                            className="p-1 text-green-400 hover:text-green-300"
                          >
                            <CheckCircle className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => setEditingItem(null)}
                            className="p-1 text-gray-400 hover:text-gray-300"
                          >
                            <AlertCircle className="w-4 h-4" />
                          </button>
                        </>
                      ) : (
                        <>
                          <div className="flex-1">
                            <p className="text-white text-sm font-medium">{item.name}</p>
                            {item.description && (
                              <p className="text-gray-400 text-xs">{item.description}</p>
                            )}
                          </div>
                          <span className={`px-2 py-1 rounded-full text-xs ${
                            item.is_active ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20 text-gray-400'
                          }`}>
                            {item.is_active ? 'Active' : 'Inactive'}
                          </span>
                          <button
                            onClick={() => setEditingItem(item)}
                            className="p-1 text-blue-400 hover:text-blue-300"
                          >
                            <Edit2 className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => handleDeleteItem(item.id)}
                            className="p-1 text-red-400 hover:text-red-300"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </>
                      )}
                    </div>
                  ))}
                  {referenceData.length === 0 && (
                    <div className="text-center py-8 text-gray-400">
                      No items found. Add some reference data or populate all tables.
                    </div>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'users' && (
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4">User Management</h3>
            <p className="text-gray-400 mb-4">User management interface coming soon...</p>
            <button
              onClick={() => router.push('/admin/users')}
              className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
            >
              <Users className="w-4 h-4" />
              View User Management Page
            </button>
          </div>
        )}

        {activeTab === 'analytics' && (
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <h3 className="text-lg font-semibold text-white mb-4">Platform Analytics</h3>
            <p className="text-gray-400 mb-4">Analytics dashboard coming soon...</p>
            <button
              onClick={() => router.push('/admin/analytics')}
              className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
            >
              <TrendingUp className="w-4 h-4" />
              View Analytics Page
            </button>
          </div>
        )}
      </div>
    </div>
  );
}