'use client';

import { useEffect, useState } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { Users, CheckCircle, XCircle, Clock, Eye, Github, Linkedin, Globe, Code2, Loader2, UserCheck, AlertCircle } from 'lucide-react';
import { DeveloperProfile } from '@/types';

export default function EngineeringManagerDashboard() {
  const { isLoaded, isSignedIn, user } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [pendingDevelopers, setPendingDevelopers] = useState<DeveloperProfile[]>([]);
  const [selectedDeveloper, setSelectedDeveloper] = useState<DeveloperProfile | null>(null);
  const [vettingNotes, setVettingNotes] = useState('');
  const [processing, setProcessing] = useState(false);
  const [stats, setStats] = useState({
    pendingCount: 0,
    approvedToday: 0,
    rejectedToday: 0,
    totalVetted: 0,
  });

  useEffect(() => {
    if (isLoaded && isSignedIn) {
      loadDashboardData();
    }
  }, [isLoaded, isSignedIn]);

  const loadDashboardData = async () => {
    try {
      // Sync with backend
      await api.auth.syncWithBackend();
      
      // Get pending developers
      const developers = await api.developers.getPendingVetting();
      setPendingDevelopers(developers.items || []);
      
      setStats({
        pendingCount: developers.items?.length || 0,
        approvedToday: 0, // Real data would come from API
        rejectedToday: 0, // Real data would come from API
        totalVetted: 0, // Real data would come from API
      });
    } catch (error) {
      console.error('Failed to load dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleVetting = async (developerId: string, status: 'approved' | 'rejected') => {
    setProcessing(true);
    
    try {
      await api.developers.vetDeveloper(developerId, {
        vetting_status: status,
        vetting_notes: vettingNotes,
      });
      
      // Remove from pending list
      setPendingDevelopers(prev => prev.filter(dev => dev.id !== developerId));
      setSelectedDeveloper(null);
      setVettingNotes('');
      
      // Update stats
      setStats(prev => ({
        ...prev,
        pendingCount: prev.pendingCount - 1,
        approvedToday: status === 'approved' ? prev.approvedToday + 1 : prev.approvedToday,
        rejectedToday: status === 'rejected' ? prev.rejectedToday + 1 : prev.rejectedToday,
        totalVetted: prev.totalVetted + 1,
      }));
    } catch (error: any) {
      console.error('Failed to vet developer:', error);
      alert(error.message || 'Failed to process vetting');
    } finally {
      setProcessing(false);
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
                <Users className="w-8 h-8 text-purple-400" />
                <span className="text-xl font-bold text-white">Engineering Manager</span>
              </div>
              <div className="flex gap-6">
                <a href="/engineering/dashboard" className="text-white font-medium">Dashboard</a>
                <a href="/engineering/developers" className="text-gray-300 hover:text-white">All Developers</a>
                <a href="/engineering/projects" className="text-gray-300 hover:text-white">Project Matching</a>
                <a href="/engineering/metrics" className="text-gray-300 hover:text-white">Metrics</a>
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
        {/* Stats Grid */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-yellow-500/20 rounded-lg flex items-center justify-center">
                <Clock className="w-6 h-6 text-yellow-400" />
              </div>
              <span className="text-2xl font-bold text-white">{stats.pendingCount}</span>
            </div>
            <p className="text-gray-400 text-sm">Pending Review</p>
          </div>

          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-green-500/20 rounded-lg flex items-center justify-center">
                <CheckCircle className="w-6 h-6 text-green-400" />
              </div>
              <span className="text-2xl font-bold text-white">{stats.approvedToday}</span>
            </div>
            <p className="text-gray-400 text-sm">Approved Today</p>
          </div>

          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-red-500/20 rounded-lg flex items-center justify-center">
                <XCircle className="w-6 h-6 text-red-400" />
              </div>
              <span className="text-2xl font-bold text-white">{stats.rejectedToday}</span>
            </div>
            <p className="text-gray-400 text-sm">Rejected Today</p>
          </div>

          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="w-12 h-12 bg-purple-500/20 rounded-lg flex items-center justify-center">
                <UserCheck className="w-6 h-6 text-purple-400" />
              </div>
              <span className="text-2xl font-bold text-white">{stats.totalVetted}</span>
            </div>
            <p className="text-gray-400 text-sm">Total Vetted</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Pending Developers List */}
          <div className="lg:col-span-1">
            <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
              <h2 className="text-xl font-semibold text-white mb-4">Pending Vetting</h2>
              
              {pendingDevelopers.length > 0 ? (
                <div className="space-y-3">
                  {pendingDevelopers.map((developer) => (
                    <button
                      key={developer.id}
                      onClick={() => setSelectedDeveloper(developer)}
                      className={`w-full text-left p-4 rounded-lg border transition-all ${
                        selectedDeveloper?.id === developer.id
                          ? 'bg-purple-500/20 border-purple-500/40'
                          : 'bg-white/5 border-white/10 hover:bg-white/10'
                      }`}
                    >
                      <div className="flex items-start justify-between">
                        <div>
                          <p className="text-white font-medium">{developer.primary_role}</p>
                          <p className="text-gray-400 text-sm">{developer.years_experience} years exp</p>
                          {developer.country && (
                            <p className="text-gray-500 text-xs mt-1">{developer.country}</p>
                          )}
                        </div>
                        <Eye className="w-4 h-4 text-gray-400" />
                      </div>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8">
                  <AlertCircle className="w-12 h-12 text-gray-600 mx-auto mb-4" />
                  <p className="text-gray-400">No pending developers</p>
                  <p className="text-gray-500 text-sm mt-2">Check back later for new applications</p>
                </div>
              )}
            </div>
          </div>

          {/* Developer Details */}
          <div className="lg:col-span-2">
            <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
              {selectedDeveloper ? (
                <>
                  <div className="mb-6">
                    <h2 className="text-xl font-semibold text-white mb-4">Developer Profile Review</h2>
                    
                    {/* Basic Info */}
                    <div className="grid grid-cols-2 gap-4 mb-6">
                      <div>
                        <p className="text-gray-400 text-sm">Primary Role</p>
                        <p className="text-white font-medium">{selectedDeveloper.primary_role}</p>
                      </div>
                      <div>
                        <p className="text-gray-400 text-sm">Experience</p>
                        <p className="text-white font-medium">{selectedDeveloper.years_experience} years</p>
                      </div>
                      <div>
                        <p className="text-gray-400 text-sm">Hourly Rate</p>
                        <p className="text-white font-medium">${selectedDeveloper.hourly_rate || 'Not specified'}/hr</p>
                      </div>
                      <div>
                        <p className="text-gray-400 text-sm">Location</p>
                        <p className="text-white font-medium">{selectedDeveloper.country || 'Not specified'}</p>
                      </div>
                    </div>

                    {/* Tech Stack */}
                    {selectedDeveloper.tech_stack && selectedDeveloper.tech_stack.length > 0 && (
                      <div className="mb-6">
                        <p className="text-gray-400 text-sm mb-2">Tech Stack</p>
                        <div className="flex flex-wrap gap-2">
                          {selectedDeveloper.tech_stack.map((tech) => (
                            <span
                              key={tech}
                              className="px-3 py-1 bg-blue-500/20 border border-blue-500/30 rounded-full text-blue-300 text-sm"
                            >
                              {tech}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Bio */}
                    {selectedDeveloper.bio && (
                      <div className="mb-6">
                        <p className="text-gray-400 text-sm mb-2">Bio</p>
                        <p className="text-gray-300">{selectedDeveloper.bio}</p>
                      </div>
                    )}

                    {/* Links */}
                    <div className="grid grid-cols-3 gap-4 mb-6">
                      {selectedDeveloper.github_username && (
                        <a
                          href={`https://github.com/${selectedDeveloper.github_username}`}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-2 px-3 py-2 bg-white/10 border border-white/20 rounded-lg hover:bg-white/20 transition-colors"
                        >
                          <Github className="w-4 h-4 text-gray-400" />
                          <span className="text-gray-300 text-sm">GitHub</span>
                        </a>
                      )}
                      {selectedDeveloper.linkedin_url && (
                        <a
                          href={selectedDeveloper.linkedin_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-2 px-3 py-2 bg-white/10 border border-white/20 rounded-lg hover:bg-white/20 transition-colors"
                        >
                          <Linkedin className="w-4 h-4 text-gray-400" />
                          <span className="text-gray-300 text-sm">LinkedIn</span>
                        </a>
                      )}
                      {selectedDeveloper.portfolio_url && (
                        <a
                          href={selectedDeveloper.portfolio_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="flex items-center gap-2 px-3 py-2 bg-white/10 border border-white/20 rounded-lg hover:bg-white/20 transition-colors"
                        >
                          <Globe className="w-4 h-4 text-gray-400" />
                          <span className="text-gray-300 text-sm">Portfolio</span>
                        </a>
                      )}
                    </div>

                    {/* Vetting Notes */}
                    <div className="mb-6">
                      <label htmlFor="vetting_notes" className="block text-sm font-medium text-gray-300 mb-2">
                        Vetting Notes (Optional)
                      </label>
                      <textarea
                        id="vetting_notes"
                        rows={3}
                        value={vettingNotes}
                        onChange={(e) => setVettingNotes(e.target.value)}
                        className="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-purple-400"
                        placeholder="Add notes about your decision or feedback for the developer..."
                      />
                    </div>

                    {/* Action Buttons */}
                    <div className="flex gap-4">
                      <button
                        onClick={() => handleVetting(selectedDeveloper.id, 'approved')}
                        disabled={processing}
                        className="flex-1 inline-flex items-center justify-center gap-2 px-6 py-3 bg-green-600 hover:bg-green-700 disabled:bg-green-800 text-white font-medium rounded-lg transition-colors"
                      >
                        {processing ? (
                          <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                          <CheckCircle className="w-4 h-4" />
                        )}
                        Approve Developer
                      </button>
                      <button
                        onClick={() => handleVetting(selectedDeveloper.id, 'rejected')}
                        disabled={processing}
                        className="flex-1 inline-flex items-center justify-center gap-2 px-6 py-3 bg-red-600 hover:bg-red-700 disabled:bg-red-800 text-white font-medium rounded-lg transition-colors"
                      >
                        {processing ? (
                          <Loader2 className="w-4 h-4 animate-spin" />
                        ) : (
                          <XCircle className="w-4 h-4" />
                        )}
                        Reject Developer
                      </button>
                    </div>
                  </div>
                </>
              ) : (
                <div className="text-center py-16">
                  <Code2 className="w-16 h-16 text-gray-600 mx-auto mb-4" />
                  <p className="text-gray-400 text-lg">Select a developer to review</p>
                  <p className="text-gray-500 text-sm mt-2">Click on any pending developer from the list</p>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}