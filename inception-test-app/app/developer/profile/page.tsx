'use client';

import { useEffect, useState } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { Code2, Save, ArrowLeft, Loader2, Github, Linkedin, Globe, DollarSign, User, Zap, Hash, FileText, Award } from 'lucide-react';
import { DeveloperProfile } from '@/types';
import FileUpload from '@/components/FileUpload';

export default function DeveloperProfilePage() {
  const { isLoaded, isSignedIn } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [profile, setProfile] = useState<DeveloperProfile | null>(null);
  const [techStacks, setTechStacks] = useState<any[]>([]);
  const [developerRoles, setDeveloperRoles] = useState<any[]>([]);
  const [experienceLevels, setExperienceLevels] = useState<any[]>([]);
  
  const [formData, setFormData] = useState({
    primary_role: '',
    years_experience: '',
    tech_stack: [] as string[],
    github_username: '',
    linkedin_url: '',
    portfolio_url: '',
    hourly_rate: '',
    bio: '',
    country: '',
    availability_status: 'available' as 'available' | 'busy' | 'not_available',
  });
  
  const [uploadedResume, setUploadedResume] = useState<string[]>([]);
  const [uploadedPortfolio, setUploadedPortfolio] = useState<string[]>([]);
  const [uploadedCertificates, setUploadedCertificates] = useState<string[]>([]);

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      loadData();
    }
  }, [isLoaded, isSignedIn]);

  const loadData = async () => {
    try {
      // Load reference data
      const [techs, roles, levels] = await Promise.all([
        api.reference.getTechStacks(),
        api.reference.getDeveloperRoles(),
        api.reference.getExperienceLevels(),
      ]);
      
      setTechStacks(techs);
      setDeveloperRoles(roles);
      setExperienceLevels(levels);

      // Try to load existing profile
      try {
        const profileData = await api.developers.getProfile();
        setProfile(profileData);
        setFormData({
          primary_role: profileData.primary_role || '',
          years_experience: profileData.years_experience?.toString() || '',
          tech_stack: profileData.tech_stack || [],
          github_username: profileData.github_username || '',
          linkedin_url: profileData.linkedin_url || '',
          portfolio_url: profileData.portfolio_url || '',
          hourly_rate: profileData.hourly_rate?.toString() || '',
          bio: profileData.bio || '',
          country: profileData.country || '',
          availability_status: profileData.availability_status || 'available',
        });
      } catch (error) {
        console.log('No existing profile');
      }
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

  const handleResumeUpload = async (files: File[]) => {
    // In a real app, this would upload to a backend service
    // For now, we'll simulate the upload
    console.log('Uploading resume:', files);
    
    // Simulate upload delay
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    // Add file names to uploaded list
    const fileNames = files.map(f => f.name);
    setUploadedResume(fileNames);
  };

  const handlePortfolioUpload = async (files: File[]) => {
    console.log('Uploading portfolio files:', files);
    await new Promise(resolve => setTimeout(resolve, 1500));
    const fileNames = files.map(f => f.name);
    setUploadedPortfolio(prev => [...prev, ...fileNames]);
  };

  const handleCertificateUpload = async (files: File[]) => {
    console.log('Uploading certificates:', files);
    await new Promise(resolve => setTimeout(resolve, 1500));
    const fileNames = files.map(f => f.name);
    setUploadedCertificates(prev => [...prev, ...fileNames]);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);

    try {
      const data = {
        ...formData,
        years_experience: parseInt(formData.years_experience),
        hourly_rate: formData.hourly_rate ? parseFloat(formData.hourly_rate) : undefined,
      };

      if (profile) {
        // Update existing profile
        await api.developers.updateProfile(data);
      } else {
        // Create new profile
        await api.developers.create(data);
      }

      router.push('/developer/dashboard');
    } catch (error: any) {
      console.error('Failed to save profile:', error);
      alert(error.message || 'Failed to save profile');
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
                <Code2 className="w-8 h-8 text-green-400" />
                <span className="text-xl font-bold text-white">Inception Developer</span>
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
            onClick={() => router.push('/developer/dashboard')}
            className="inline-flex items-center gap-2 text-gray-300 hover:text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Dashboard
          </button>
        </div>

        <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-2xl p-8">
          <div className="flex items-center gap-3 mb-6">
            <div className="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
              <Code2 className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">
                {profile ? 'Edit Developer Profile' : 'Create Developer Profile'}
              </h1>
              <p className="text-gray-400 text-sm">Tell us about your skills and experience. Fields marked with <span className="text-red-400">*</span> are required.</p>
            </div>
          </div>

          {profile?.vetting_status === 'pending' && (
            <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4 mb-6">
              <p className="text-yellow-300 text-sm">
                Your profile is under review. You can still update your information.
              </p>
            </div>
          )}

          {profile?.vetting_status === 'rejected' && (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4 mb-6">
              <p className="text-red-300 text-sm">
                Please update your profile based on feedback: {profile.vetting_notes || 'Check your email'}
              </p>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Primary Role and Experience */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="primary_role" className="block text-sm font-medium text-gray-300 mb-2">
                  <User className="inline w-4 h-4 mr-1" />
                  Primary Role <span className="text-red-400">*</span>
                </label>
                <select
                  id="primary_role"
                  required
                  value={formData.primary_role}
                  onChange={(e) => setFormData({ ...formData, primary_role: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-green-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="" className="bg-gray-900 text-gray-400">Select role</option>
                  {developerRoles.map((role) => (
                    <option key={role.id} value={role.name} className="bg-gray-900 text-white">
                      {role.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="years_experience" className="block text-sm font-medium text-gray-300 mb-2">
                  <Zap className="inline w-4 h-4 mr-1" />
                  Years of Experience <span className="text-red-400">*</span>
                </label>
                <input
                  type="number"
                  id="years_experience"
                  required
                  min="0"
                  max="50"
                  value={formData.years_experience}
                  onChange={(e) => setFormData({ ...formData, years_experience: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-green-400"
                  placeholder="5"
                />
              </div>
            </div>

            {/* Tech Stack */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                <Hash className="inline w-4 h-4 mr-1" />
                Tech Stack <span className="text-red-400">*</span> <span className="text-gray-500 text-xs">(Select all that apply)</span>
              </label>
              <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                {techStacks.map((tech) => (
                  <label
                    key={tech.id}
                    className={`flex items-center justify-center px-3 py-2 rounded-lg border cursor-pointer transition-all ${
                      formData.tech_stack.includes(tech.name)
                        ? 'bg-green-500/20 border-green-500/40 text-green-300'
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

            {/* Social Links */}
            <div className="space-y-4">
              <label className="block text-sm font-medium text-gray-300">
                Professional Links <span className="text-gray-500 text-xs">(optional)</span>
              </label>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <Github className="w-4 h-4 text-gray-400" />
                    <span className="text-sm text-gray-400">GitHub Username</span>
                  </div>
                  <input
                    type="text"
                    placeholder="johndoe"
                    value={formData.github_username}
                    onChange={(e) => setFormData({ ...formData, github_username: e.target.value })}
                    className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-green-400"
                  />
                </div>

                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <Linkedin className="w-4 h-4 text-gray-400" />
                    <span className="text-sm text-gray-400">LinkedIn URL</span>
                  </div>
                  <input
                    type="url"
                    placeholder="https://linkedin.com/in/..."
                    value={formData.linkedin_url}
                    onChange={(e) => setFormData({ ...formData, linkedin_url: e.target.value })}
                    className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-green-400"
                  />
                </div>

                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <Globe className="w-4 h-4 text-gray-400" />
                    <span className="text-sm text-gray-400">Portfolio URL</span>
                  </div>
                  <input
                    type="url"
                    placeholder="https://portfolio.com"
                    value={formData.portfolio_url}
                    onChange={(e) => setFormData({ ...formData, portfolio_url: e.target.value })}
                    className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-green-400"
                  />
                </div>
              </div>
            </div>

            {/* Hourly Rate and Availability */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div>
                <label htmlFor="hourly_rate" className="block text-sm font-medium text-gray-300 mb-2">
                  <DollarSign className="inline w-4 h-4 mr-1" />
                  Hourly Rate (USD) <span className="text-gray-500 text-xs">(optional)</span>
                </label>
                <input
                  type="number"
                  id="hourly_rate"
                  min="0"
                  step="5"
                  value={formData.hourly_rate}
                  onChange={(e) => setFormData({ ...formData, hourly_rate: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-green-400"
                  placeholder="75"
                />
              </div>

              <div>
                <label htmlFor="country" className="block text-sm font-medium text-gray-300 mb-2">
                  Country <span className="text-gray-500 text-xs">(optional)</span>
                </label>
                <input
                  type="text"
                  id="country"
                  value={formData.country}
                  onChange={(e) => setFormData({ ...formData, country: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-green-400"
                  placeholder="United States"
                />
              </div>

              <div>
                <label htmlFor="availability_status" className="block text-sm font-medium text-gray-300 mb-2">
                  Availability <span className="text-gray-500 text-xs">(optional)</span>
                </label>
                <select
                  id="availability_status"
                  value={formData.availability_status}
                  onChange={(e) => setFormData({ ...formData, availability_status: e.target.value as any })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-green-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="available" className="bg-gray-900 text-white">Available</option>
                  <option value="busy" className="bg-gray-900 text-white">Busy</option>
                  <option value="not_available" className="bg-gray-900 text-white">Not Available</option>
                </select>
              </div>
            </div>

            {/* Bio */}
            <div>
              <label htmlFor="bio" className="block text-sm font-medium text-gray-300 mb-2">
                Bio / Professional Summary <span className="text-gray-500 text-xs">(optional)</span>
              </label>
              <textarea
                id="bio"
                rows={5}
                value={formData.bio}
                onChange={(e) => setFormData({ ...formData, bio: e.target.value })}
                className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-green-400"
                placeholder="Tell us about your experience, what you specialize in, and what makes you a great developer..."
              />
            </div>

            {/* File Uploads Section */}
            <div className="space-y-6 pt-6 border-t border-white/10">
              <h3 className="text-lg font-semibold text-white flex items-center gap-2">
                <FileText className="w-5 h-5 text-green-400" />
                Documents & Portfolio
              </h3>

              {/* Resume Upload */}
              <FileUpload
                label="Resume/CV (optional)"
                description="Upload your resume or CV (PDF, DOC, DOCX)"
                accept=".pdf,.doc,.docx"
                maxSize={5}
                multiple={false}
                onUpload={handleResumeUpload}
                uploadedFiles={uploadedResume}
              />

              {/* Portfolio Upload */}
              <FileUpload
                label="Portfolio Files (optional)"
                description="Upload portfolio items, project screenshots, or demo videos"
                accept="image/*,video/*,.pdf,.zip"
                maxSize={20}
                multiple={true}
                onUpload={handlePortfolioUpload}
                uploadedFiles={uploadedPortfolio}
              />

              {/* Certificates Upload */}
              <FileUpload
                label="Certificates & Achievements (optional)"
                description="Upload certificates, awards, or credentials"
                accept="image/*,.pdf"
                maxSize={10}
                multiple={true}
                onUpload={handleCertificateUpload}
                uploadedFiles={uploadedCertificates}
              />
            </div>

            {/* Submit Button */}
            <div className="flex justify-end gap-4">
              <button
                type="button"
                onClick={() => router.push('/developer/dashboard')}
                className="px-6 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={saving || formData.tech_stack.length === 0}
                className="inline-flex items-center gap-2 px-6 py-2 bg-green-600 hover:bg-green-700 disabled:bg-green-800 text-white font-medium rounded-lg transition-colors"
              >
                {saving ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Save className="w-4 h-4" />
                )}
                {saving ? 'Saving...' : profile ? 'Update Profile' : 'Create Profile'}
              </button>
            </div>

            {!profile && (
              <p className="text-center text-gray-400 text-sm">
                After creating your profile, it will be reviewed by our engineering team for approval.
              </p>
            )}
          </form>
        </div>
      </div>
    </div>
  );
}