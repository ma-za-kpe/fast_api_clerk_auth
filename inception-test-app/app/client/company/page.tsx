'use client';

import { useEffect, useState } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { Building2, Save, ArrowLeft, Loader2, Globe, MapPin, Users, Briefcase, Image } from 'lucide-react';
import { Company } from '@/types';
import FileUpload from '@/components/FileUpload';

export default function CompanyProfilePage() {
  const { isLoaded, isSignedIn } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [company, setCompany] = useState<Company | null>(null);
  const [companySizes, setCompanySizes] = useState<any[]>([]);
  const [businessTypes, setBusinessTypes] = useState<any[]>([]);
  
  const [formData, setFormData] = useState({
    name: '',
    size_id: '',
    business_type_id: '',
    location_country: '',
    state_region: '',
    city: '',
    website: '',
    description: '',
  });
  
  const [uploadedLogo, setUploadedLogo] = useState<string[]>([]);

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      syncAndLoadData();
    }
  }, [isLoaded, isSignedIn]);

  const syncAndLoadData = async () => {
    try {
      // First sync with backend to ensure user is registered as CLIENT
      console.log('Syncing with backend as CLIENT user...');
      await api.auth.syncWithBackend();
      console.log('Successfully synced with backend');
      // Then load the data
      await loadData();
    } catch (error) {
      console.error('Failed to sync with backend:', error);
      alert('Please make sure you are signed up as a CLIENT user. You may need to sign up again through the proper flow.');
    }
  };

  const loadData = async () => {
    try {
      // Load reference data
      const [sizes, types] = await Promise.all([
        api.reference.getCompanySizes(),
        api.reference.getBusinessTypes(),
      ]);
      
      setCompanySizes(sizes);
      setBusinessTypes(types);

      // Try to load existing company
      try {
        const companyData = await api.companies.get();
        setCompany(companyData);
        setFormData({
          name: companyData.name || '',
          size_id: companyData.size_id?.toString() || '',
          business_type_id: companyData.business_type_id?.toString() || '',
          location_country: companyData.location_country || '',
          state_region: companyData.state_region || '',
          city: companyData.city || '',
          website: companyData.website || '',
          description: companyData.description || '',
        });
      } catch (error) {
        console.log('No existing company profile');
      }
    } catch (error) {
      console.error('Failed to load data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleLogoUpload = async (files: File[]) => {
    // In a real app, this would upload to a backend service
    console.log('Uploading logo:', files);
    
    // Simulate upload delay
    await new Promise(resolve => setTimeout(resolve, 1500));
    
    // Add file names to uploaded list (only one logo allowed)
    const fileName = files[0]?.name;
    if (fileName) {
      setUploadedLogo([fileName]);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);

    try {
      const data: any = {
        name: formData.name,
        description: formData.description || '',
        website: formData.website || '',
        location_country: formData.location_country || '',
        state_region: formData.state_region || '',
        city: formData.city || '',
      };

      // Only add these fields if they have values
      if (formData.size_id) {
        data.size_id = parseInt(formData.size_id);
      }
      if (formData.business_type_id) {
        data.business_type_id = parseInt(formData.business_type_id);
      }
      if (uploadedLogo[0]) {
        data.logo = uploadedLogo[0];
      }

      console.log('Saving company with data:', data);

      if (company) {
        // Update existing company
        await api.companies.update(company.id, data);
      } else {
        // Create new company
        await api.companies.create(data);
      }

      router.push('/client/dashboard');
    } catch (error: any) {
      console.error('Failed to save company:', error);
      alert(error.message || 'Failed to save company profile');
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
      <div className="max-w-3xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
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
            <div className="w-12 h-12 bg-blue-500/20 rounded-lg flex items-center justify-center">
              <Building2 className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">
                {company ? 'Edit Company Profile' : 'Create Company Profile'}
              </h1>
              <p className="text-gray-400 text-sm">Tell us about your company. Fields marked with <span className="text-red-400">*</span> are required.</p>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Company Logo Upload */}
            <FileUpload
              label="Company Logo (optional)"
              description="Upload your company logo (PNG, JPG, SVG)"
              accept="image/*"
              maxSize={2}
              multiple={false}
              onUpload={handleLogoUpload}
              uploadedFiles={uploadedLogo}
            />

            {/* Company Name */}
            <div>
              <label htmlFor="name" className="block text-sm font-medium text-gray-300 mb-2">
                Company Name <span className="text-red-400">*</span>
              </label>
              <input
                type="text"
                id="name"
                required
                value={formData.name}
                onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                placeholder="TechCorp Inc."
              />
            </div>

            {/* Company Size and Business Type */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label htmlFor="size_id" className="block text-sm font-medium text-gray-300 mb-2">
                  <Users className="inline w-4 h-4 mr-1" />
                  Company Size <span className="text-gray-500 text-xs">(optional)</span>
                </label>
                <select
                  id="size_id"
                  value={formData.size_id}
                  onChange={(e) => setFormData({ ...formData, size_id: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="" className="bg-gray-900 text-gray-400">Select size</option>
                  {companySizes.map((size) => (
                    <option key={size.id} value={size.id} className="bg-gray-900 text-white">
                      {size.display_name || size.name}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label htmlFor="business_type_id" className="block text-sm font-medium text-gray-300 mb-2">
                  <Briefcase className="inline w-4 h-4 mr-1" />
                  Business Type <span className="text-gray-500 text-xs">(optional)</span>
                </label>
                <select
                  id="business_type_id"
                  value={formData.business_type_id}
                  onChange={(e) => setFormData({ ...formData, business_type_id: e.target.value })}
                  className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
                >
                  <option value="" className="bg-gray-900 text-gray-400">Select type</option>
                  {businessTypes.map((type) => (
                    <option key={type.id} value={type.id} className="bg-gray-900 text-white">
                      {type.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Location */}
            <div className="space-y-4">
              <label className="block text-sm font-medium text-gray-300">
                <MapPin className="inline w-4 h-4 mr-1" />
                Location <span className="text-gray-500 text-xs">(optional)</span>
              </label>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <input
                  type="text"
                  placeholder="Country"
                  value={formData.location_country}
                  onChange={(e) => setFormData({ ...formData, location_country: e.target.value })}
                  className="px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                />
                <input
                  type="text"
                  placeholder="State/Province"
                  value={formData.state_region}
                  onChange={(e) => setFormData({ ...formData, state_region: e.target.value })}
                  className="px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                />
                <input
                  type="text"
                  placeholder="City"
                  value={formData.city}
                  onChange={(e) => setFormData({ ...formData, city: e.target.value })}
                  className="px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                />
              </div>
            </div>

            {/* Website */}
            <div>
              <label htmlFor="website" className="block text-sm font-medium text-gray-300 mb-2">
                <Globe className="inline w-4 h-4 mr-1" />
                Website <span className="text-gray-500 text-xs">(optional)</span>
              </label>
              <input
                type="url"
                id="website"
                value={formData.website}
                onChange={(e) => setFormData({ ...formData, website: e.target.value })}
                className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                placeholder="https://example.com"
              />
            </div>

            {/* Description */}
            <div>
              <label htmlFor="description" className="block text-sm font-medium text-gray-300 mb-2">
                Company Description <span className="text-gray-500 text-xs">(optional)</span>
              </label>
              <textarea
                id="description"
                rows={4}
                value={formData.description}
                onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                placeholder="Tell us about your company, what you do, and what makes you unique..."
              />
            </div>

            {/* Submit Button */}
            <div className="flex justify-end gap-4">
              <button
                type="button"
                onClick={() => router.push('/client/dashboard')}
                className="px-6 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white font-medium transition-colors"
              >
                Cancel
              </button>
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
                {saving ? 'Saving...' : 'Save Profile'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
}