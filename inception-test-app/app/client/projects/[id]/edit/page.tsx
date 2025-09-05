'use client';

import { useEffect, useState } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter, useParams } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { 
  Building2, ArrowLeft, Save, Loader2, AlertCircle,
  Briefcase, DollarSign, Clock, Hash, FileText, Target 
} from 'lucide-react';
import { Project } from '@/types';

export default function EditProjectPage() {
  const { isLoaded, isSignedIn } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const params = useParams();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [project, setProject] = useState<Project | null>(null);
  const [error, setError] = useState<string | null>(null);
  
  // Reference data
  const [projectTypes, setProjectTypes] = useState<any[]>([]);
  const [projectCategories, setProjectCategories] = useState<any[]>([]);
  const [projectScopes, setProjectScopes] = useState<any[]>([]);
  const [techStacks, setTechStacks] = useState<any[]>([]);
  const [experienceLevels, setExperienceLevels] = useState<any[]>([]);
  const [budgetTypes, setBudgetTypes] = useState<any[]>([]);
  
  const [formData, setFormData] = useState({
    title: '',
    description: '',
    project_type_ids: [] as number[],
    category_id: '',
    scope: '',
    budget_type: '',
    budget_amount: '',
    budget_currency: 'USD',
    hourly_rate_min: '',
    hourly_rate_max: '',
    tech_stack_ids: [] as number[],
    experience_level: '',
    deadline: '',
    is_urgent: false,
  });

  const projectId = params.id as string;

  useEffect(() => {
    if (isLoaded && isSignedIn && projectId) {
      loadData();
    }
  }, [isLoaded, isSignedIn, projectId]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Load project and reference data in parallel
      const [
        projectData,
        projectTypesData,
        projectCategoriesData, 
        projectScopesData,
        techStacksData,
        experienceLevelsData,
        budgetTypesData
      ] = await Promise.all([
        api.projects.get(projectId),
        api.reference.getProjectTypes(),
        api.reference.getProjectCategories(),
        api.reference.getProjectScopes(),
        api.reference.getTechStacks(),
        api.reference.getExperienceLevels(),
        api.reference.getBudgetTypes(),
      ]);

      // Check if project can be edited
      if (projectData.status !== 'draft') {
        setError('Only draft projects can be edited');
        return;
      }

      setProject(projectData);
      setProjectTypes(projectTypesData);
      setProjectCategories(projectCategoriesData);
      setProjectScopes(projectScopesData);
      setTechStacks(techStacksData);
      setExperienceLevels(experienceLevelsData);
      setBudgetTypes(budgetTypesData);

      // Populate form with existing data
      setFormData({
        title: projectData.title || '',
        description: projectData.description || '',
        project_type_ids: (projectData.project_types || []).map((pt: any) => pt.id),
        category_id: projectData.category?.id?.toString() || '',
        scope: projectData.scope?.name || '',
        budget_type: projectData.budget_type?.name || '',
        budget_amount: projectData.budget_amount?.toString() || '',
        budget_currency: projectData.budget_currency || 'USD',
        hourly_rate_min: projectData.hourly_rate_min?.toString() || '',
        hourly_rate_max: projectData.hourly_rate_max?.toString() || '',
        tech_stack_ids: (projectData.tech_stacks || []).map((ts: any) => ts.id),
        experience_level: projectData.experience_level?.name || '',
        deadline: projectData.deadline ? projectData.deadline.split('T')[0] : '',
        is_urgent: projectData.is_urgent || false,
      });

    } catch (error: any) {
      console.error('Failed to load project data:', error);
      setError(error.message || 'Failed to load project data');
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!project) return;
    
    try {
      setSaving(true);
      
      // Get selected objects for proper mapping
      const selectedScope = projectScopes.find(s => s.name === formData.scope);
      const selectedExperience = experienceLevels.find(l => l.name === formData.experience_level);
      const selectedBudgetType = budgetTypes.find(b => b.name === formData.budget_type);

      const updateData: any = {
        title: formData.title,
        description: formData.description,
        category_id: parseInt(formData.category_id),
        scope: selectedScope?.name || formData.scope,
        experience_level: selectedExperience?.name || formData.experience_level,
        budget_type: selectedBudgetType?.name || formData.budget_type,
        budget_amount: parseFloat(formData.budget_amount),
        budget_currency: formData.budget_currency,
        tech_stack_ids: formData.tech_stack_ids,
        project_type_ids: formData.project_type_ids,
        is_urgent: formData.is_urgent,
      };

      // Only add deadline if it exists
      if (formData.deadline) {
        updateData.deadline = new Date(formData.deadline).toISOString();
      }

      // Add hourly rates if budget type is hourly
      if (selectedBudgetType?.name.toLowerCase().includes('hourly')) {
        if (formData.hourly_rate_min) {
          updateData.hourly_rate_min = parseFloat(formData.hourly_rate_min);
        }
        if (formData.hourly_rate_max) {
          updateData.hourly_rate_max = parseFloat(formData.hourly_rate_max);
        }
      }

      console.log('Sending update data:', updateData);
      await api.projects.update(projectId, updateData);
      router.push(`/client/projects/${projectId}`);
      
    } catch (error: any) {
      console.error('Failed to update project:', error);
      console.error('Update data was:', updateData);
      alert(error.message || 'Failed to update project');
    } finally {
      setSaving(false);
    }
  };

  const handleTechStackChange = (techStackId: number) => {
    setFormData(prev => ({
      ...prev,
      tech_stack_ids: prev.tech_stack_ids.includes(techStackId)
        ? prev.tech_stack_ids.filter(id => id !== techStackId)
        : [...prev.tech_stack_ids, techStackId]
    }));
  };

  const handleProjectTypeChange = (projectTypeId: number) => {
    setFormData(prev => ({
      ...prev,
      project_type_ids: prev.project_type_ids.includes(projectTypeId)
        ? prev.project_type_ids.filter(id => id !== projectTypeId)
        : [...prev.project_type_ids, projectTypeId]
    }));
  };

  if (!isLoaded || loading) {
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

  if (error) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-6 text-center">
            <AlertCircle className="w-12 h-12 text-red-400 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-red-300 mb-2">Cannot Edit Project</h2>
            <p className="text-gray-300 mb-4">{error}</p>
            <button
              onClick={() => router.push(`/client/projects/${projectId}`)}
              className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Project
            </button>
          </div>
        </div>
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
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <button
            onClick={() => router.push(`/client/projects/${projectId}`)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Project
          </button>
          <div>
            <h1 className="text-3xl font-bold text-white">Edit Project</h1>
            <p className="text-gray-300">{project?.title}</p>
          </div>
        </div>

        {/* Form */}
        <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-8">
          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Basic Info */}
            <div className="grid grid-cols-1 gap-6">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Project Title <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={formData.title}
                  onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                  placeholder="Enter project title..."
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Project Description <span className="text-red-400">*</span>
                </label>
                <textarea
                  required
                  rows={6}
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                  placeholder="Describe your project in detail..."
                />
              </div>
            </div>

            {/* Project Details */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Category <span className="text-red-400">*</span>
                </label>
                <select
                  required
                  value={formData.category_id}
                  onChange={(e) => setFormData({ ...formData, category_id: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="">Select Category</option>
                  {projectCategories.map(category => (
                    <option key={category.id} value={category.id}>
                      {category.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Project Scope <span className="text-red-400">*</span>
                </label>
                <select
                  required
                  value={formData.scope}
                  onChange={(e) => setFormData({ ...formData, scope: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="">Select Scope</option>
                  {projectScopes.map(scope => (
                    <option key={scope.id} value={scope.name}>
                      {scope.display_name || scope.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Experience Level <span className="text-red-400">*</span>
                </label>
                <select
                  required
                  value={formData.experience_level}
                  onChange={(e) => setFormData({ ...formData, experience_level: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="">Select Experience Level</option>
                  {experienceLevels.map(level => (
                    <option key={level.id} value={level.name}>
                      {level.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Budget Type <span className="text-red-400">*</span>
                </label>
                <select
                  required
                  value={formData.budget_type}
                  onChange={(e) => setFormData({ ...formData, budget_type: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="">Select Budget Type</option>
                  {budgetTypes.map(type => (
                    <option key={type.id} value={type.name}>
                      {type.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Budget */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Budget Amount <span className="text-red-400">*</span>
                </label>
                <input
                  type="number"
                  required
                  min="0"
                  step="0.01"
                  value={formData.budget_amount}
                  onChange={(e) => setFormData({ ...formData, budget_amount: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                  placeholder="0.00"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Currency</label>
                <select
                  value={formData.budget_currency}
                  onChange={(e) => setFormData({ ...formData, budget_currency: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="USD">USD</option>
                  <option value="EUR">EUR</option>
                  <option value="GBP">GBP</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Deadline <span className="text-gray-500">(optional)</span>
                </label>
                <input
                  type="date"
                  value={formData.deadline}
                  onChange={(e) => setFormData({ ...formData, deadline: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400"
                />
              </div>
            </div>

            {/* Hourly Rates (if budget type is hourly) */}
            {formData.budget_type.toLowerCase().includes('hourly') && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Min Hourly Rate <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="number"
                    required
                    min="0"
                    step="0.01"
                    value={formData.hourly_rate_min}
                    onChange={(e) => setFormData({ ...formData, hourly_rate_min: e.target.value })}
                    className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                    placeholder="0.00"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">
                    Max Hourly Rate <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="number"
                    required
                    min="0"
                    step="0.01"
                    value={formData.hourly_rate_max}
                    onChange={(e) => setFormData({ ...formData, hourly_rate_max: e.target.value })}
                    className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                    placeholder="0.00"
                  />
                </div>
              </div>
            )}

            {/* Tech Stack */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-3">
                Technology Stack <span className="text-red-400">*</span>
              </label>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3 max-h-64 overflow-y-auto">
                {techStacks.map(tech => (
                  <label key={tech.id} className="flex items-center gap-3 p-3 bg-white/5 rounded-lg hover:bg-white/10 cursor-pointer transition-colors">
                    <input
                      type="checkbox"
                      checked={formData.tech_stack_ids.includes(tech.id)}
                      onChange={() => handleTechStackChange(tech.id)}
                      className="w-4 h-4 text-purple-600 bg-white/10 border-white/20 rounded focus:ring-purple-500"
                    />
                    <span className="text-white text-sm">{tech.name}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Project Types */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-3">
                Project Types <span className="text-red-400">*</span>
              </label>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                {projectTypes.map(type => (
                  <label key={type.id} className="flex items-center gap-3 p-3 bg-white/5 rounded-lg hover:bg-white/10 cursor-pointer transition-colors">
                    <input
                      type="checkbox"
                      checked={formData.project_type_ids.includes(type.id)}
                      onChange={() => handleProjectTypeChange(type.id)}
                      className="w-4 h-4 text-purple-600 bg-white/10 border-white/20 rounded focus:ring-purple-500"
                    />
                    <span className="text-white text-sm">{type.name}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Urgent Flag */}
            <div className="flex items-center gap-3">
              <input
                type="checkbox"
                id="is_urgent"
                checked={formData.is_urgent}
                onChange={(e) => setFormData({ ...formData, is_urgent: e.target.checked })}
                className="w-4 h-4 text-red-600 bg-white/10 border-white/20 rounded focus:ring-red-500"
              />
              <label htmlFor="is_urgent" className="text-white">
                Mark as urgent project
              </label>
            </div>

            {/* Submit Button */}
            <div className="flex gap-4 pt-6">
              <button
                type="button"
                onClick={() => router.push(`/client/projects/${projectId}`)}
                className="px-6 py-3 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving}
                className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-800 text-white font-medium rounded-lg transition-colors"
              >
                {saving ? (
                  <Loader2 className="w-5 h-5 animate-spin" />
                ) : (
                  <Save className="w-5 h-5" />
                )}
                {saving ? 'Saving...' : 'Save Changes'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}