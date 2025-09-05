'use client';

import { useEffect, useState } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { Building2, Save, ArrowLeft, Loader2, Briefcase, DollarSign, Clock, Hash, FileText, Target } from 'lucide-react';
import { Company } from '@/types';

export default function NewProjectPage() {
  const { isLoaded, isSignedIn } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [company, setCompany] = useState<Company | null>(null);
  
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
    project_type_id: '',
    project_category_id: '',
    project_scope_id: '',
    budget_type: '',
    budget_amount: '',
    tech_stack: [] as string[],
    experience_level: '',
    expected_duration: '',
    requirements: '',
  });

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      loadData();
    }
  }, [isLoaded, isSignedIn]);

  const loadData = async () => {
    try {
      // Sync with backend to ensure user profile exists
      try {
        await api.auth.syncWithBackend();
        console.log('User profile synced');
      } catch (error) {
        console.log('Profile sync not required or already synced');
      }

      // Check if company exists
      try {
        const companyData = await api.companies.get();
        setCompany(companyData);
      } catch (error) {
        // No company, redirect to create one
        alert('Please create your company profile first');
        router.push('/client/company');
        return;
      }

      // Load reference data
      const [types, categories, scopes, techs, levels, budgets] = await Promise.all([
        api.reference.getProjectTypes(),
        api.reference.getProjectCategories(),
        api.reference.getProjectScopes(),
        api.reference.getTechStacks(),
        api.reference.getExperienceLevels(),
        api.reference.getBudgetTypes(),
      ]);
      
      setProjectTypes(types);
      setProjectCategories(categories);
      setProjectScopes(scopes);
      setTechStacks(techs);
      setExperienceLevels(levels);
      setBudgetTypes(budgets);
    } catch (error) {
      console.error('Failed to load data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleTechStackToggle = (tech: string) => {
    setFormData(prev => ({
      ...prev,
      tech_stack: prev.tech_stack.includes(tech)
        ? prev.tech_stack.filter(t => t !== tech)
        : [...prev.tech_stack, tech]
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);

    try {
      // Get tech stack IDs from names
      const techStackIds = formData.tech_stack.map(name => {
        const tech = techStacks.find(t => t.name === name);
        return tech?.id;
      }).filter(id => id !== undefined);

      // Get the string names from IDs for fields that expect strings
      const selectedScope = projectScopes.find(s => s.id === parseInt(formData.project_scope_id || '0'));
      const selectedExperience = experienceLevels.find(l => l.id === parseInt(formData.experience_level || '0'));
      const selectedBudgetType = budgetTypes.find(b => b.id === parseInt(formData.budget_type || '0'));
      
      const data: any = {
        title: formData.title,
        description: formData.description + (formData.requirements ? '\n\nRequirements:\n' + formData.requirements : ''),
        category_id: formData.project_category_id ? parseInt(formData.project_category_id) : 1,
        scope: selectedScope?.name || 'less_than_6_months',
        experience_level: selectedExperience?.name || 'Entry',
        budget_type: selectedBudgetType?.name || 'fixed',
        budget_amount: parseFloat(formData.budget_amount || '1000'),
        tech_stack_ids: techStackIds.length > 0 ? techStackIds : [1],
        project_type_ids: formData.project_type_id ? [parseInt(formData.project_type_id)] : [1],
      };

      console.log('Creating project with data:', data);
      console.log('Available scopes:', projectScopes);
      console.log('Available experience levels:', experienceLevels);
      console.log('Available budget types:', budgetTypes);

      const result = await api.projects.create(data);
      router.push('/client/projects');
    } catch (error: any) {
      console.error('Failed to create project:', error);
      alert(error.message || 'Failed to create project');
    } finally {
      setSaving(false);
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
            </div>
            <button
              onClick={() => signOut()}
              className="px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white text-sm transition-colors"
            >
              Sign Out
            </button>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-6">
          <button
            onClick={() => router.push('/client/dashboard')}
            className="inline-flex items-center gap-2 text-gray-300 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Dashboard
          </button>
        </div>

        <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-2xl p-8">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
              <Briefcase className="w-6 h-6 text-purple-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">Create New Project</h1>
              <p className="text-gray-400 text-sm">Post a project to find talented developers. Fields marked with <span className="text-red-400">*</span> are required.</p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Project Title */}
            <div>
              <label htmlFor="title" className="block text-sm font-medium text-gray-300 mb-2">
                Project Title <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                id="title"
                required
                value={formData.title}
                onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                placeholder="E.g., E-commerce Website Development"
              />
            </div>

            {/* Project Type, Category, and Scope */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <label htmlFor="project_type_id" className="block text-sm font-medium text-gray-300 mb-2">
                  <Target className="inline w-4 h-4 mr-1" />
                  Project Type <span className="text-gray-500 text-xs">(optional)</span>
                </label>
                <select
                  id="project_type_id"
                  value={formData.project_type_id}
                  onChange={(e) => setFormData({ ...formData, project_type_id: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="" className="bg-gray-900 text-gray-400">Select type</option>
                  {projectTypes.map((type) => (
                    <option key={type.id} value={type.id} className="bg-gray-900 text-white">
                      {type.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="project_category_id" className="block text-sm font-medium text-gray-300 mb-2">
                  Category <span className="text-gray-500 text-xs">(optional)</span>
                </label>
                <select
                  id="project_category_id"
                  value={formData.project_category_id}
                  onChange={(e) => setFormData({ ...formData, project_category_id: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="" className="bg-gray-900 text-gray-400">Select category</option>
                  {projectCategories.map((category) => (
                    <option key={category.id} value={category.id} className="bg-gray-900 text-white">
                      {category.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="project_scope_id" className="block text-sm font-medium text-gray-300 mb-2">
                  Scope <span className="text-gray-500 text-xs">(optional)</span>
                </label>
                <select
                  id="project_scope_id"
                  value={formData.project_scope_id}
                  onChange={(e) => setFormData({ ...formData, project_scope_id: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="" className="bg-gray-900 text-gray-400">Select scope</option>
                  {projectScopes.map((scope) => (
                    <option key={scope.id} value={scope.id} className="bg-gray-900 text-white">
                      {scope.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Description */}
            <div>
              <label htmlFor="description" className="block text-sm font-medium text-gray-300 mb-2">
                <FileText className="inline w-4 h-4 mr-1" />
                Project Description <span className="text-red-400">*</span>
              </label>
              <textarea
                id="description"
                required
                rows={5}
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                placeholder="Describe your project in detail. What needs to be built? What are the main features?"
              />
            </div>

            {/* Budget */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="budget_type" className="block text-sm font-medium text-gray-300 mb-2">
                  <DollarSign className="inline w-4 h-4 mr-1" />
                  Budget Type <span className="text-red-400">*</span>
                </label>
                <select
                  id="budget_type"
                  value={formData.budget_type}
                  onChange={(e) => setFormData({ ...formData, budget_type: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="" className="bg-gray-900 text-gray-400">Select budget type</option>
                  {budgetTypes.map((type) => (
                    <option key={type.id} value={type.id} className="bg-gray-900 text-white">
                      {type.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="budget_amount" className="block text-sm font-medium text-gray-300 mb-2">
                  Budget Amount (USD) <span className="text-gray-500 text-xs">(optional)</span>
                </label>
                <input
                  type="number"
                  id="budget_amount"
                  min="0"
                  step="100"
                  value={formData.budget_amount}
                  onChange={(e) => setFormData({ ...formData, budget_amount: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                  placeholder={formData.budget_type === 'hourly' ? '50-100' : '5000'}
                />
              </div>
            </div>

            {/* Duration and Experience */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="expected_duration" className="block text-sm font-medium text-gray-300 mb-2">
                  <Clock className="inline w-4 h-4 mr-1" />
                  Expected Duration <span className="text-gray-500 text-xs">(optional)</span>
                </label>
                <input
                  type="text"
                  id="expected_duration"
                  value={formData.expected_duration}
                  onChange={(e) => setFormData({ ...formData, expected_duration: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                  placeholder="E.g., 3 months"
                />
              </div>

              <div>
                <label htmlFor="experience_level" className="block text-sm font-medium text-gray-300 mb-2">
                  Experience Level Required <span className="text-gray-500 text-xs">(optional)</span>
                </label>
                <select
                  id="experience_level"
                  value={formData.experience_level}
                  onChange={(e) => setFormData({ ...formData, experience_level: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="" className="bg-gray-900 text-gray-400">Any level</option>
                  {experienceLevels.map((level) => (
                    <option key={level.id} value={level.id} className="bg-gray-900 text-white">
                      {level.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Tech Stack */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                <Hash className="inline w-4 h-4 mr-1" />
                Required Tech Stack <span className="text-gray-500 text-xs">(optional)</span>
              </label>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {techStacks.map((tech) => (
                  <label
                    key={tech.id}
                    className={`flex items-center justify-center px-3 py-2 rounded-lg border cursor-pointer transition-all ${
                      formData.tech_stack.includes(tech.name)
                        ? 'bg-purple-500/20 border-purple-500/40 text-purple-300'
                        : 'bg-white/5 border-white/20 text-gray-400 hover:bg-white/10'
                    }`}
                  >
                    <input
                      type="checkbox"
                      className="hidden"
                      checked={formData.tech_stack.includes(tech.name)}
                      onChange={() => handleTechStackToggle(tech.name)}
                    />
                    <span className="text-sm">{tech.name}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Additional Requirements */}
            <div>
              <label htmlFor="requirements" className="block text-sm font-medium text-gray-300 mb-2">
                Additional Requirements <span className="text-gray-500 text-xs">(optional)</span>
              </label>
              <textarea
                id="requirements"
                rows={3}
                value={formData.requirements}
                onChange={(e) => setFormData({ ...formData, requirements: e.target.value })}
                className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                placeholder="Any specific requirements, qualifications, or preferences for developers?"
              />
            </div>

            {/* Submit Buttons */}
            <div className="flex justify-between">
              <button
                type="button"
                onClick={() => router.push('/client/dashboard')}
                className="px-6 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white font-medium transition-colors"
              >
                Cancel
              </button>
              <div className="flex gap-4">
                <button
                  type="submit"
                  disabled={saving}
                  className="inline-flex items-center gap-2 px-6 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-800 text-white font-medium rounded-lg transition-colors"
                >
                  {saving ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <Save className="w-4 h-4" />
                  )}
                  {saving ? 'Creating...' : 'Create Project'}
                </button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}