'use client';

import { useEffect, useState } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { Building2, Plus, Briefcase, Users, DollarSign, TrendingUp, Clock, CheckCircle, Loader2, Shield } from 'lucide-react';
import { Company, Project } from '@/types';

export default function ClientDashboard() {
  const { isLoaded, isSignedIn, user } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [company, setCompany] = useState<Company | null>(null);
  const [projects, setProjects] = useState<Project[]>([]);
  const [stats, setStats] = useState({
    activeProjects: 0,
    totalSpent: 0,
    developersHired: 0,
    completedProjects: 0,
  });

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      loadDashboardData();
    }
  }, [isLoaded, isSignedIn]);

  const loadDashboardData = async () => {
    try {
      // Load data in parallel to reduce loading time
      const [companyData, projectsData] = await Promise.all([
        api.companies.get().catch(() => null),
        api.projects.list().catch(() => null),
      ]);
      
      // Set company data
      if (companyData) {
        setCompany(companyData);
      }
      
      // Set projects and calculate stats
      if (projectsData) {
        setProjects(projectsData.projects || []);
        
        const active = projectsData.projects?.filter((p: Project) => p.status === 'active').length || 0;
        const completed = projectsData.projects?.filter((p: Project) => p.status === 'completed').length || 0;
        
        setStats({
          activeProjects: active,
          totalSpent: projectsData.total_spent || 0,
          developersHired: projectsData.developers_hired || 0,
          completedProjects: completed,
        });
      }
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  if (!isLoaded || loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
        <Loader2 className="w-12 h-12 text-white animate-spin" />
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
                <Building2 className="w-8 h-8 text-purple-400" />
                <span className="text-xl font-bold text-white">Inception Platform</span>
              </div>
              <div className="flex gap-6">
                <a href="/client/dashboard" className="text-white font-medium">Dashboard</a>
                <a href="/client/company" className="text-gray-300 hover:text-white">Company</a>
                <a href="/client/projects" className="text-gray-300 hover:text-white">Projects</a>
                <a href="/client/developers" className="text-gray-300 hover:text-white">Find Developers</a>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <span className="text-sm text-gray-300">
                {user?.firstName} {user?.lastName}
              </span>
              {user?.publicMetadata?.is_admin && (
                <button
                  onClick={() => router.push('/admin/dashboard')}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 rounded-lg text-white text-sm font-medium transition-colors"
                >
                  <Shield className="w-4 h-4" />
                  Admin Panel
                </button>
              )}
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
        {/* Welcome Section */}
        {!company && (
          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-6 mb-8">
            <h2 className="text-xl font-semibold text-yellow-300 mb-2">Complete Your Profile</h2>
            <p className="text-gray-300 mb-4">
              Create your company profile to start posting projects and hiring developers.
            </p>
            <a
              href="/client/company"
              className="inline-flex items-center gap-2 px-4 py-2 bg-yellow-500 hover:bg-yellow-600 text-black font-medium rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              Create Company Profile
            </a>
          </div>
        )}

        {/* Admin Access Notification */}
        {user?.publicMetadata?.is_admin && (
          <div className="bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/20 rounded-xl p-6 mb-8">
            <div className="flex items-start gap-4">
              <div className="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center flex-shrink-0">
                <Shield className="w-6 h-6 text-purple-400" />
              </div>
              <div className="flex-1">
                <h2 className="text-xl font-semibold text-purple-300 mb-2">Admin Access Available</h2>
                <p className="text-gray-300 mb-4">
                  You have administrator privileges. Access the admin panel to manage platform settings, reference data, and user accounts.
                </p>
                <button
                  onClick={() => router.push('/admin/dashboard')}
                  className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
                >
                  <Shield className="w-4 h-4" />
                  Go to Admin Dashboard
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
          {loading ? (
            // Loading skeleton
            Array(4).fill(0).map((_, i) => (
              <div key={i} className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="w-12 h-12 bg-gray-500/20 rounded-lg animate-pulse"></div>
                  <div className="w-16 h-8 bg-gray-500/20 rounded animate-pulse"></div>
                </div>
                <div className="h-4 bg-gray-500/20 rounded w-2/3 animate-pulse"></div>
              </div>
            ))
          ) : (
            // Actual stats
            <>
              <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
                <Briefcase className="w-6 h-6 text-blue-400" />
              </div>
              <span className="text-2xl font-bold text-white">{stats.activeProjects}</span>
            </div>
            <p className="text-gray-400 text-sm">Active Projects</p>
          </div>

          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                <DollarSign className="w-6 h-6 text-green-400" />
              </div>
              <span className="text-2xl font-bold text-white">${stats.totalSpent.toLocaleString()}</span>
            </div>
            <p className="text-gray-400 text-sm">Total Spent</p>
          </div>

          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
                <Users className="w-6 h-6 text-purple-400" />
              </div>
              <span className="text-2xl font-bold text-white">{stats.developersHired}</span>
            </div>
            <p className="text-gray-400 text-sm">Developers Hired</p>
          </div>

          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-orange-500/20 rounded-lg flex items-center justify-center">
                <CheckCircle className="w-6 h-6 text-orange-400" />
              </div>
              <span className="text-2xl font-bold text-white">{stats.completedProjects}</span>
            </div>
            <p className="text-gray-400 text-sm">Completed Projects</p>
          </div>
            </>
          )}
        </div>

        {/* Company Info */}
        {loading ? (
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6 mb-8">
            <div className="flex items-center justify-between mb-4">
              <div className="h-6 bg-gray-500/20 rounded w-32 animate-pulse"></div>
              <div className="h-4 bg-gray-500/20 rounded w-20 animate-pulse"></div>
            </div>
            <div className="grid gap-4">
              <div>
                <div className="h-4 bg-gray-500/20 rounded w-24 mb-1 animate-pulse"></div>
                <div className="h-5 bg-gray-500/20 rounded w-48 animate-pulse"></div>
              </div>
              <div>
                <div className="h-4 bg-gray-500/20 rounded w-16 mb-1 animate-pulse"></div>
                <div className="h-4 bg-gray-500/20 rounded w-64 animate-pulse"></div>
              </div>
            </div>
          </div>
        ) : company ? (
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6 mb-8">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-semibold text-white">Company Profile</h2>
              <a
                href="/client/company"
                className="text-purple-400 hover:text-purple-300 text-sm"
              >
                Edit Profile
              </a>
            </div>
            <div className="grid gap-4">
              <div>
                <p className="text-gray-400 text-sm mb-1">Company Name</p>
                <p className="text-white font-medium">{company.name}</p>
              </div>
              {company.website && (
                <div>
                  <p className="text-gray-400 text-sm mb-1">Website</p>
                  <a href={company.website} target="_blank" rel="noopener noreferrer" className="text-purple-400 hover:text-purple-300">
                    {company.website}
                  </a>
                </div>
              )}
              {company.description && (
                <div>
                  <p className="text-gray-400 text-sm mb-1">Description</p>
                  <p className="text-gray-300">{company.description}</p>
                </div>
              )}
            </div>
          </div>
        ) : null}

        {/* Recent Projects */}
        <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-white">Recent Projects</h2>
            {company && (
              <a
                href="/client/projects/new"
                className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
              >
                <Plus className="w-4 h-4" />
                New Project
              </a>
            )}
          </div>

          {loading ? (
            <div className="grid gap-4">
              {Array(3).fill(0).map((_, i) => (
                <div key={i} className="bg-white/5 border border-white/10 rounded-lg p-4 animate-pulse">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="h-5 bg-gray-500/20 rounded w-48 mb-2"></div>
                      <div className="h-4 bg-gray-500/20 rounded w-full mb-1"></div>
                      <div className="h-4 bg-gray-500/20 rounded w-3/4 mb-3"></div>
                      <div className="flex items-center gap-4">
                        <div className="h-3 bg-gray-500/20 rounded w-20"></div>
                        <div className="h-3 bg-gray-500/20 rounded w-16"></div>
                        <div className="h-6 bg-gray-500/20 rounded-full w-16"></div>
                      </div>
                    </div>
                    <div className="w-4 h-4 bg-gray-500/20 rounded"></div>
                  </div>
                </div>
              ))}
            </div>
          ) : projects.length > 0 ? (
            <div className="grid gap-4">
              {projects.slice(0, 5).map((project) => (
                <div
                  key={project.id}
                  className="bg-white/5 border border-white/10 rounded-lg p-4 hover:bg-white/10 transition-colors cursor-pointer"
                  onClick={() => router.push(`/client/projects/${project.id}`)}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <h3 className="text-white font-medium mb-1">{project.title}</h3>
                      <p className="text-gray-400 text-sm line-clamp-2">{project.description}</p>
                      <div className="flex items-center gap-4 mt-3">
                        <span className="text-xs text-gray-500">
                          Budget: ${project.budget_amount?.toLocaleString() || 'TBD'}
                        </span>
                        <span className="text-xs text-gray-500">
                          Type: {project.budget_type}
                        </span>
                        <span className={`text-xs px-2 py-1 rounded-full ${
                          project.status === 'active' ? 'bg-green-500/20 text-green-400' :
                          project.status === 'completed' ? 'bg-blue-500/20 text-blue-400' :
                          'bg-gray-500/20 text-gray-400'
                        }`}>
                          {project.status}
                        </span>
                      </div>
                    </div>
                    <Clock className="w-4 h-4 text-gray-500" />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-12">
              <Briefcase className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400 mb-4">No projects yet</p>
              {company && (
                <a
                  href="/client/projects/new"
                  className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
                >
                  <Plus className="w-4 h-4" />
                  Create Your First Project
                </a>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}