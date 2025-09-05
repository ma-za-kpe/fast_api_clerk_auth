'use client';

import { useEffect, useState } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { 
  Users, Search, Filter, Star, MapPin, DollarSign, 
  Clock, Code2, CheckCircle, Building2, Loader2,
  Github, Globe, Mail, Award, Briefcase
} from 'lucide-react';

interface Developer {
  id: string;
  user_id: string;
  first_name?: string;
  last_name?: string;
  role_id?: number;
  role_name?: string;
  bio?: string;
  github_username?: string;
  linkedin_url?: string;
  portfolio_url?: string;
  years_of_experience?: number;
  hourly_rate?: number;
  availability_status?: string;
  tech_stacks?: any[];
  vetting_status?: string;
  rating?: number;
  completed_projects?: number;
  location?: string;
}

export default function ClientDevelopersPage() {
  const { isLoaded, isSignedIn, user } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [developers, setDevelopers] = useState<Developer[]>([]);
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedTechStacks, setSelectedTechStacks] = useState<string[]>([]);
  const [experienceFilter, setExperienceFilter] = useState('all');
  const [availabilityFilter, setAvailabilityFilter] = useState('all');
  const [techStacks, setTechStacks] = useState<any[]>([]);

  useEffect(() => {
    if (isLoaded && !isSignedIn) {
      router.push('/sign-in');
    }
  }, [isLoaded, isSignedIn]);

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      loadData();
    }
  }, [isLoaded, isSignedIn]);

  const loadData = async () => {
    try {
      setLoading(true);
      // Load tech stacks for filter
      const techStacksData = await api.reference.getTechStacks();
      setTechStacks(techStacksData);

      // Load approved developers
      const developersData = await api.developers.list({ 
        vetting_status: 'approved',
        availability_status: availabilityFilter !== 'all' ? availabilityFilter : undefined
      });
      setDevelopers(developersData.items || []);
    } catch (error) {
      console.error('Failed to load data:', error);
      setDevelopers([]);
    } finally {
      setLoading(false);
    }
  };

  const getAvailabilityBadge = (status: string) => {
    const config: Record<string, { color: string; text: string }> = {
      available: { color: 'bg-green-500', text: 'Available' },
      busy: { color: 'bg-yellow-500', text: 'Busy' },
      unavailable: { color: 'bg-red-500', text: 'Unavailable' },
    };

    const { color, text } = config[status] || config.unavailable;

    return (
      <span className={`inline-flex items-center gap-1 px-2 py-1 ${color}/20 border border-white/10 rounded-full text-xs text-white`}>
        <Clock className="w-3 h-3" />
        {text}
      </span>
    );
  };

  const filteredDevelopers = developers.filter(developer => {
    if (searchTerm && !developer.bio?.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !developer.first_name?.toLowerCase().includes(searchTerm.toLowerCase()) &&
        !developer.last_name?.toLowerCase().includes(searchTerm.toLowerCase())) {
      return false;
    }
    
    if (selectedTechStacks.length > 0) {
      const devTechNames = developer.tech_stacks?.map(t => t.name) || [];
      if (!selectedTechStacks.some(tech => devTechNames.includes(tech))) {
        return false;
      }
    }

    if (experienceFilter !== 'all') {
      const exp = developer.years_of_experience || 0;
      if (experienceFilter === 'junior' && exp > 2) return false;
      if (experienceFilter === 'mid' && (exp < 2 || exp > 5)) return false;
      if (experienceFilter === 'senior' && exp < 5) return false;
    }

    if (availabilityFilter !== 'all' && developer.availability_status !== availabilityFilter) {
      return false;
    }

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
                <a href="/client/projects" className="text-gray-300 hover:text-white">Projects</a>
                <a href="/client/developers" className="text-white font-medium">Find Developers</a>
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
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white mb-2">Find Developers</h1>
          <p className="text-gray-300">Browse and connect with vetted developers for your projects</p>
        </div>

        {/* Filters */}
        <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6 mb-6">
          {/* Search Bar */}
          <div className="mb-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-gray-400" />
              <input
                type="text"
                placeholder="Search by name, bio, or skills..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-purple-400"
              />
            </div>
          </div>

          {/* Filter Options */}
          <div className="grid md:grid-cols-3 gap-4">
            {/* Experience Level */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Experience Level</label>
              <select
                value={experienceFilter}
                onChange={(e) => setExperienceFilter(e.target.value)}
                className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
              >
                <option value="all" className="bg-gray-900 text-gray-400">All Levels</option>
                <option value="junior" className="bg-gray-900 text-white">Junior (0-2 years)</option>
                <option value="mid" className="bg-gray-900 text-white">Mid-level (2-5 years)</option>
                <option value="senior" className="bg-gray-900 text-white">Senior (5+ years)</option>
              </select>
            </div>

            {/* Availability */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Availability</label>
              <select
                value={availabilityFilter}
                onChange={(e) => setAvailabilityFilter(e.target.value)}
                className="w-full px-3 py-2 bg-white/10 border border-white/20 rounded-lg text-white focus:outline-none focus:border-purple-400 [&>option]:bg-gray-900 [&>option]:text-white"
              >
                <option value="all" className="bg-gray-900 text-gray-400">All</option>
                <option value="available" className="bg-gray-900 text-white">Available Now</option>
                <option value="busy" className="bg-gray-900 text-white">Currently Busy</option>
              </select>
            </div>

            {/* Tech Stack */}
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">Tech Stack</label>
              <div className="flex flex-wrap gap-2">
                {techStacks.slice(0, 5).map((tech) => (
                  <button
                    key={tech.id}
                    onClick={() => {
                      if (selectedTechStacks.includes(tech.name)) {
                        setSelectedTechStacks(selectedTechStacks.filter(t => t !== tech.name));
                      } else {
                        setSelectedTechStacks([...selectedTechStacks, tech.name]);
                      }
                    }}
                    className={`px-3 py-1 rounded-lg text-xs transition-all ${
                      selectedTechStacks.includes(tech.name)
                        ? 'bg-purple-600 text-white'
                        : 'bg-white/10 text-gray-300 hover:bg-white/20'
                    }`}
                  >
                    {tech.name}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Developers Grid */}
        {loading ? (
          <div className="flex justify-center py-12">
            <Loader2 className="w-8 h-8 text-white animate-spin" />
          </div>
        ) : filteredDevelopers.length === 0 ? (
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-12 text-center">
            <Users className="w-12 h-12 text-gray-500 mx-auto mb-4" />
            <h3 className="text-xl font-semibold text-white mb-2">No developers found</h3>
            <p className="text-gray-400">Try adjusting your search filters</p>
          </div>
        ) : (
          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredDevelopers.map((developer) => (
              <div
                key={developer.id}
                className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6 hover:bg-black/40 transition-all"
              >
                {/* Header */}
                <div className="flex justify-between items-start mb-4">
                  <div>
                    <h3 className="text-lg font-semibold text-white">
                      {developer.first_name} {developer.last_name}
                    </h3>
                    <p className="text-sm text-gray-400">{developer.role_name || 'Developer'}</p>
                  </div>
                  {getAvailabilityBadge(developer.availability_status || 'unavailable')}
                </div>

                {/* Bio */}
                <p className="text-gray-300 text-sm mb-4 line-clamp-2">
                  {developer.bio || 'No bio available'}
                </p>

                {/* Stats */}
                <div className="grid grid-cols-2 gap-4 mb-4">
                  <div>
                    <p className="text-gray-500 text-xs mb-1">Experience</p>
                    <span className="text-white font-medium">
                      {developer.years_of_experience || 0} years
                    </span>
                  </div>
                  <div>
                    <p className="text-gray-500 text-xs mb-1">Hourly Rate</p>
                    <div className="flex items-center gap-1">
                      <DollarSign className="w-4 h-4 text-green-400" />
                      <span className="text-white font-medium">
                        {developer.hourly_rate || 'Negotiable'}
                      </span>
                    </div>
                  </div>
                  <div>
                    <p className="text-gray-500 text-xs mb-1">Rating</p>
                    <div className="flex items-center gap-1">
                      <Star className="w-4 h-4 text-yellow-400 fill-current" />
                      <span className="text-white font-medium">
                        {developer.rating || '5.0'}
                      </span>
                    </div>
                  </div>
                  <div>
                    <p className="text-gray-500 text-xs mb-1">Projects</p>
                    <div className="flex items-center gap-1">
                      <Briefcase className="w-4 h-4 text-blue-400" />
                      <span className="text-white font-medium">
                        {developer.completed_projects || 0}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Tech Stack */}
                <div className="mb-4">
                  <div className="flex flex-wrap gap-1">
                    {developer.tech_stacks?.slice(0, 4).map((tech, index) => (
                      <span
                        key={index}
                        className="px-2 py-1 bg-purple-500/20 border border-purple-500/40 rounded text-xs text-purple-300"
                      >
                        {tech.name}
                      </span>
                    ))}
                    {developer.tech_stacks && developer.tech_stacks.length > 4 && (
                      <span className="px-2 py-1 text-xs text-gray-400">
                        +{developer.tech_stacks.length - 4}
                      </span>
                    )}
                  </div>
                </div>

                {/* Links */}
                <div className="flex items-center justify-between pt-4 border-t border-white/10">
                  <div className="flex gap-3">
                    {developer.github_username && (
                      <a
                        href={`https://github.com/${developer.github_username}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-gray-400 hover:text-white transition-colors"
                      >
                        <Github className="w-4 h-4" />
                      </a>
                    )}
                    {developer.portfolio_url && (
                      <a
                        href={developer.portfolio_url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-gray-400 hover:text-white transition-colors"
                      >
                        <Globe className="w-4 h-4" />
                      </a>
                    )}
                  </div>
                  <button
                    onClick={() => router.push(`/client/developers/${developer.id}`)}
                    className="inline-flex items-center gap-2 px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm font-medium rounded-lg transition-colors"
                  >
                    View Profile
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}