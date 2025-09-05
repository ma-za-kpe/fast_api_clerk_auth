'use client';

import { useEffect, useState } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { 
  Briefcase, Plus, Clock, CheckCircle, XCircle, 
  DollarSign, Calendar, Users, Search, Filter,
  ArrowRight, Loader2, Building2, Eye
} from 'lucide-react';
import { Project } from '@/types';

export default function ClientProjectsPage() {
  const { isLoaded, isSignedIn, user } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [projects, setProjects] = useState<Project[]>([]);
  const [filter, setFilter] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);
  const [advancedFilters, setAdvancedFilters] = useState({
    minBudget: '',
    maxBudget: '',
    budgetType: '',
    category: '',
    urgentOnly: false,
    hasDeadline: '',
  });

  useEffect(() => {
    if (isLoaded && !isSignedIn) {
      router.push('/sign-in');
    }
  }, [isLoaded, isSignedIn]);

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      loadProjects();
    }
  }, [isLoaded, isSignedIn]);

  const loadProjects = async () => {
    try {
      setLoading(true);
      // Load client's projects (remove client_id filter to get all projects for this user)
      const projectsData = await api.projects.list();
      console.log('Projects loaded:', projectsData);
      setProjects(projectsData.projects || []);
    } catch (error) {
      console.error('Failed to load projects:', error);
      setProjects([]);
    } finally {
      setLoading(false);
    }
  };

  const getStatusBadge = (status: string) => {
    const statusConfig: Record<string, { color: string; icon: any }> = {
      draft: { color: 'bg-gray-500', icon: Clock },
      open: { color: 'bg-green-500', icon: CheckCircle },
      active: { color: 'bg-blue-500', icon: Clock },
      in_progress: { color: 'bg-blue-500', icon: Clock },
      completed: { color: 'bg-purple-500', icon: CheckCircle },
      cancelled: { color: 'bg-red-500', icon: XCircle },
    };

    const config = statusConfig[status] || statusConfig.draft;
    const Icon = config.icon;

    return (
      <span className={`inline-flex items-center gap-1 px-2 py-1 ${config.color}/20 border border-white/10 rounded-full text-xs text-white`}>
        <Icon className="w-3 h-3" />
        {status.replace('_', ' ').toUpperCase()}
      </span>
    );
  };

  const filteredProjects = projects.filter(project => {
    // Basic filter
    if (filter !== 'all' && project.status !== filter) return false;
    
    // Search term
    if (searchTerm && !project.title.toLowerCase().includes(searchTerm.toLowerCase()) && 
        !project.description.toLowerCase().includes(searchTerm.toLowerCase())) return false;
    
    // Advanced filters
    if (advancedFilters.minBudget && project.budget_amount && project.budget_amount < parseFloat(advancedFilters.minBudget)) return false;
    if (advancedFilters.maxBudget && project.budget_amount && project.budget_amount > parseFloat(advancedFilters.maxBudget)) return false;
    if (advancedFilters.budgetType && (typeof project.budget_type === 'string' ? project.budget_type : project.budget_type?.name) !== advancedFilters.budgetType) return false;
    if (advancedFilters.category && project.category?.name !== advancedFilters.category) return false;
    if (advancedFilters.urgentOnly && !project.is_urgent) return false;
    if (advancedFilters.hasDeadline === 'yes' && !project.deadline) return false;
    if (advancedFilters.hasDeadline === 'no' && project.deadline) return false;
    
    return true;
  });

  if (!isLoaded) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
        <Loader2 className="w-8 h-8 text-white animate-spin" />
      </div>
    );
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
                <span className="text-xl font-bold text-white">Client Portal</span>
              </div>
              <div className="flex items-center gap-6">
                <a href="/client/dashboard" className="text-gray-300 hover:text-white">Dashboard</a>
                <a href="/client/company" className="text-gray-300 hover:text-white">Company</a>
                <a href="/client/projects" className="text-white font-medium">Projects</a>
                <a href="/client/developers" className="text-gray-300 hover:text-white">Find Developers</a>
              </div>
            </div>
            <div className="flex items-center gap-4">
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
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">My Projects</h1>
            <p className="text-gray-300">Manage your projects and track progress</p>
          </div>
          <a
            href="/client/projects/new"
            className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-700 hover:to-pink-700 text-white font-medium rounded-lg transition-all"
          >
            <Plus className="w-5 h-5" />
            New Project
          </a>
        </div>

        {/* Filters */}
        <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6 mb-6">
          <div className="flex flex-col gap-4">
            {/* Basic Filters */}
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
                  <input
                    type="text"
                    placeholder="Search projects by title or description..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-purple-400"
                  />
                </div>
              </div>
              <button
                onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
                className={`px-4 py-2 rounded-lg transition-all ${
                  showAdvancedFilters 
                    ? 'bg-purple-600 text-white' 
                    : 'bg-white/10 text-gray-300 hover:bg-white/20'
                }`}
              >
                <Filter className="w-4 h-4 inline mr-2" />
                Advanced Filters
              </button>
            </div>

            {/* Status Filters */}
            <div className="flex flex-wrap gap-2">
              <button
                onClick={() => setFilter('all')}
                className={`px-4 py-2 rounded-lg transition-all ${
                  filter === 'all' 
                    ? 'bg-purple-600 text-white' 
                    : 'bg-white/10 text-gray-300 hover:bg-white/20'
                }`}
              >
                All
              </button>
              <button
                onClick={() => setFilter('draft')}
                className={`px-4 py-2 rounded-lg transition-all ${
                  filter === 'draft' 
                    ? 'bg-purple-600 text-white' 
                    : 'bg-white/10 text-gray-300 hover:bg-white/20'
                }`}
              >
                Draft
              </button>
              <button
                onClick={() => setFilter('active')}
                className={`px-4 py-2 rounded-lg transition-all ${
                  filter === 'active' 
                    ? 'bg-purple-600 text-white' 
                    : 'bg-white/10 text-gray-300 hover:bg-white/20'
                }`}
              >
                Active
              </button>
              <button
                onClick={() => setFilter('in_progress')}
                className={`px-4 py-2 rounded-lg transition-all ${
                  filter === 'in_progress' 
                    ? 'bg-purple-600 text-white' 
                    : 'bg-white/10 text-gray-300 hover:bg-white/20'
                }`}
              >
                In Progress
              </button>
              <button
                onClick={() => setFilter('completed')}
                className={`px-4 py-2 rounded-lg transition-all ${
                  filter === 'completed' 
                    ? 'bg-purple-600 text-white' 
                    : 'bg-white/10 text-gray-300 hover:bg-white/20'
                }`}
              >
                Completed
              </button>
            </div>

            {/* Advanced Filters */}
            {showAdvancedFilters && (
              <div className="border-t border-white/10 pt-4 mt-4">
                <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-4">
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Min Budget</label>
                    <input
                      type="number"
                      placeholder="0"
                      value={advancedFilters.minBudget}
                      onChange={(e) => setAdvancedFilters({...advancedFilters, minBudget: e.target.value})}
                      className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Max Budget</label>
                    <input
                      type="number"
                      placeholder="∞"
                      value={advancedFilters.maxBudget}
                      onChange={(e) => setAdvancedFilters({...advancedFilters, maxBudget: e.target.value})}
                      className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Budget Type</label>
                    <select
                      value={advancedFilters.budgetType}
                      onChange={(e) => setAdvancedFilters({...advancedFilters, budgetType: e.target.value})}
                      className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                    >
                      <option value="">Any Type</option>
                      <option value="fixed">Fixed Price</option>
                      <option value="hourly">Hourly Rate</option>
                      <option value="milestone">Milestone</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Category</label>
                    <select
                      value={advancedFilters.category}
                      onChange={(e) => setAdvancedFilters({...advancedFilters, category: e.target.value})}
                      className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                    >
                      <option value="">Any Category</option>
                      <option value="Web Development">Web Development</option>
                      <option value="Mobile Development">Mobile Development</option>
                      <option value="Desktop Development">Desktop Development</option>
                      <option value="DevOps">DevOps</option>
                      <option value="AI/ML">AI/ML</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm text-gray-400 mb-1">Deadline</label>
                    <select
                      value={advancedFilters.hasDeadline}
                      onChange={(e) => setAdvancedFilters({...advancedFilters, hasDeadline: e.target.value})}
                      className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                    >
                      <option value="">Any</option>
                      <option value="yes">Has Deadline</option>
                      <option value="no">No Deadline</option>
                    </select>
                  </div>
                  <div className="flex items-end">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={advancedFilters.urgentOnly}
                        onChange={(e) => setAdvancedFilters({...advancedFilters, urgentOnly: e.target.checked})}
                        className="w-4 h-4 text-purple-600 bg-white/10 border-white/20 rounded focus:ring-purple-500"
                      />
                      <span className="text-white text-sm">Urgent Only</span>
                    </label>
                  </div>
                </div>
                <div className="flex gap-2 mt-4">
                  <button
                    onClick={() => setAdvancedFilters({
                      minBudget: '',
                      maxBudget: '',
                      budgetType: '',
                      category: '',
                      urgentOnly: false,
                      hasDeadline: '',
                    })}
                    className="px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white text-sm transition-colors"
                  >
                    Clear Filters
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Projects Grid */}
        {loading ? (
          <div className="flex justify-center py-12">
            <Loader2 className="w-8 h-8 text-white animate-spin" />
          </div>
        ) : filteredProjects.length === 0 ? (
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-12 text-center">
            <Briefcase className="w-12 h-12 text-gray-500 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-white mb-2">No projects found</h3>
            <p className="text-gray-400 mb-6">
              {searchTerm || filter !== 'all' 
                ? 'Try adjusting your filters' 
                : 'Get started by creating your first project'}
            </p>
            {!searchTerm && filter === 'all' && (
              <a
                href="/client/projects/new"
                className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
              >
                <Plus className="w-4 h-4" />
                Create Project
              </a>
            )}
          </div>
        ) : (
          <div className="grid gap-6">
            {filteredProjects.map((project) => (
              <div
                key={project.id}
                className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6 hover:bg-black/40 transition-all"
              >
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-xl font-semibold text-white">{project.title}</h3>
                      {project.is_urgent && (
                        <span className="px-2 py-1 bg-red-500/20 border border-red-500/40 rounded-full text-xs text-red-300 font-medium">
                          URGENT
                        </span>
                      )}
                    </div>
                    <p className="text-gray-400 text-sm">Project #{project.code_name}</p>
                  </div>
                  {getStatusBadge(project.status)}
                </div>

                <p className="text-gray-300 mb-4 line-clamp-2">{project.description}</p>

                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
                  <div>
                    <p className="text-gray-500 text-xs mb-1">Budget</p>
                    <div className="flex items-center gap-1">
                      <DollarSign className="w-4 h-4 text-green-400" />
                      <span className="text-white font-medium">
                        ${project.budget_amount?.toLocaleString()}
                      </span>
                    </div>
                  </div>
                  <div>
                    <p className="text-gray-500 text-xs mb-1">Type</p>
                    <span className="text-white">{typeof project.budget_type === 'string' ? project.budget_type : project.budget_type?.name || 'N/A'}</span>
                  </div>
                  <div>
                    <p className="text-gray-500 text-xs mb-1">Deadline</p>
                    <div className="flex items-center gap-1">
                      <Calendar className="w-4 h-4 text-yellow-400" />
                      <span className="text-white">
                        {project.deadline ? new Date(project.deadline).toLocaleDateString() : 'No deadline'}
                      </span>
                    </div>
                  </div>
                  <div>
                    <p className="text-gray-500 text-xs mb-1">Applicants</p>
                    <div className="flex items-center gap-1">
                      <Users className="w-4 h-4 text-blue-400" />
                      <span className="text-white">{project.bid_count || 0}</span>
                    </div>
                  </div>
                </div>

                <div className="flex justify-between items-center pt-4 border-t border-white/10">
                  <div className="flex gap-2">
                    {(project.tech_stacks || project.tech_stack || []).slice(0, 3).map((tech, index) => (
                      <span
                        key={index}
                        className="px-2 py-1 bg-purple-500/20 border border-purple-500/40 rounded text-xs text-purple-300"
                      >
                        {typeof tech === 'string' ? tech : tech.name}
                      </span>
                    ))}
                    {(project.tech_stacks || project.tech_stack || []).length > 3 && (
                      <span className="px-2 py-1 text-xs text-gray-400">
                        +{(project.tech_stacks || project.tech_stack || []).length - 3} more
                      </span>
                    )}
                  </div>
                  <a
                    href={`/client/projects/${project.id}`}
                    className="inline-flex items-center gap-2 px-3 py-1 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white text-sm transition-colors"
                  >
                    <Eye className="w-4 h-4" />
                    View Details
                  </a>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}