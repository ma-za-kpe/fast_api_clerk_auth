'use client';

import { useEffect, useState } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter, useParams } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { 
  Building2, ArrowLeft, Edit2, Trash2, Upload, Download, 
  Clock, CheckCircle, DollarSign, Calendar, Users, 
  Eye, Globe, Lock, AlertCircle, Loader2, Send,
  FileText, Image, Archive
} from 'lucide-react';
import { Project } from '@/types';

export default function ProjectDetailsPage() {
  const { isLoaded, isSignedIn, user } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const params = useParams();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [project, setProject] = useState<Project | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [publishing, setPublishing] = useState(false);

  const projectId = params.id as string;

  useEffect(() => {
    if (isLoaded && isSignedIn && projectId) {
      loadProject();
    }
  }, [isLoaded, isSignedIn, projectId]);

  const loadProject = async () => {
    try {
      setLoading(true);
      setError(null);
      const projectData = await api.projects.get(projectId);
      setProject(projectData);
    } catch (error: any) {
      console.error('Failed to load project:', error);
      setError(error.message || 'Failed to load project');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async () => {
    if (!project || project.status !== 'draft') {
      alert('Only draft projects can be deleted');
      return;
    }
    
    if (!confirm(`Are you sure you want to delete "${project.title}"? This action cannot be undone.`)) {
      return;
    }

    try {
      setDeleting(true);
      await api.projects.delete(projectId);
      router.push('/client/projects');
    } catch (error: any) {
      console.error('Failed to delete project:', error);
      alert(error.message || 'Failed to delete project');
    } finally {
      setDeleting(false);
    }
  };

  const handlePublish = async () => {
    if (!project || project.status !== 'draft') {
      alert('Only draft projects can be published');
      return;
    }

    if (!confirm(`Are you sure you want to publish "${project.title}"? Once published, the project cannot be edited.`)) {
      return;
    }

    try {
      setPublishing(true);
      await api.projects.publish(projectId);
      await loadProject(); // Reload to show updated status
    } catch (error: any) {
      console.error('Failed to publish project:', error);
      alert(error.message || 'Failed to publish project');
    } finally {
      setPublishing(false);
    }
  };

  const getStatusBadge = (status: string) => {
    const statusConfig: Record<string, { color: string; icon: any; label: string }> = {
      draft: { color: 'bg-gray-500', icon: Clock, label: 'Draft' },
      active: { color: 'bg-green-500', icon: CheckCircle, label: 'Active' },
      in_progress: { color: 'bg-blue-500', icon: Clock, label: 'In Progress' },
      completed: { color: 'bg-purple-500', icon: CheckCircle, label: 'Completed' },
      cancelled: { color: 'bg-red-500', icon: AlertCircle, label: 'Cancelled' },
    };

    const config = statusConfig[status] || statusConfig.draft;
    const Icon = config.icon;

    return (
      <span className={`inline-flex items-center gap-2 px-3 py-1 ${config.color}/20 border border-white/10 rounded-full text-sm text-white`}>
        <Icon className="w-4 h-4" />
        {config.label}
      </span>
    );
  };

  const canEdit = project?.status === 'draft';
  const canDelete = project?.status === 'draft';
  const canPublish = project?.status === 'draft';

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
            <h2 className="text-xl font-semibold text-red-300 mb-2">Error Loading Project</h2>
            <p className="text-gray-300 mb-4">{error}</p>
            <button
              onClick={() => router.push('/client/projects')}
              className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Projects
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!project) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900">
        <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6 text-center">
            <h2 className="text-xl font-semibold text-white mb-2">Project Not Found</h2>
            <p className="text-gray-300 mb-4">The project you're looking for doesn't exist or you don't have permission to view it.</p>
            <button
              onClick={() => router.push('/client/projects')}
              className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to Projects
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
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <button
            onClick={() => router.push('/client/projects')}
            className="inline-flex items-center gap-2 px-4 py-2 bg-white/10 hover:bg-white/20 border border-white/20 rounded-lg text-white transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Projects
          </button>
          <div className="flex-1">
            <h1 className="text-3xl font-bold text-white">{project.title}</h1>
            <p className="text-gray-300">Project #{project.code_name}</p>
          </div>
          {getStatusBadge(project.status)}
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap gap-3 mb-8">
          {canEdit && (
            <button
              onClick={() => router.push(`/client/projects/${projectId}/edit`)}
              className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg transition-colors"
            >
              <Edit2 className="w-4 h-4" />
              Edit Project
            </button>
          )}
          
          {canPublish && (
            <button
              onClick={handlePublish}
              disabled={publishing}
              className="inline-flex items-center gap-2 px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-green-800 text-white font-medium rounded-lg transition-colors"
            >
              {publishing ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Send className="w-4 h-4" />
              )}
              {publishing ? 'Publishing...' : 'Publish Project'}
            </button>
          )}

          <button
            onClick={() => router.push(`/client/projects/${projectId}/attachments`)}
            className="inline-flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white font-medium rounded-lg transition-colors"
          >
            <Upload className="w-4 h-4" />
            Manage Files
          </button>

          {canDelete && (
            <button
              onClick={handleDelete}
              disabled={deleting}
              className="inline-flex items-center gap-2 px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-red-800 text-white font-medium rounded-lg transition-colors"
            >
              {deleting ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Trash2 className="w-4 h-4" />
              )}
              {deleting ? 'Deleting...' : 'Delete Project'}
            </button>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Main Content */}
          <div className="lg:col-span-2 space-y-6">
            {/* Project Description */}
            <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
              <h2 className="text-xl font-semibold text-white mb-4">Project Description</h2>
              <p className="text-gray-300 leading-relaxed whitespace-pre-wrap">{project.description}</p>
            </div>

            {/* Tech Stack */}
            {(project.tech_stacks || project.tech_stack) && (
              <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">Technology Stack</h2>
                <div className="flex flex-wrap gap-2">
                  {(project.tech_stacks || project.tech_stack || []).map((tech, index) => (
                    <span
                      key={index}
                      className="px-3 py-1 bg-purple-500/20 border border-purple-500/40 rounded-full text-sm text-purple-300"
                    >
                      {typeof tech === 'string' ? tech : tech.name}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Project Types */}
            {project.project_types && project.project_types.length > 0 && (
              <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">Project Types</h2>
                <div className="flex flex-wrap gap-2">
                  {project.project_types.map((type, index) => (
                    <span
                      key={index}
                      className="px-3 py-1 bg-blue-500/20 border border-blue-500/40 rounded-full text-sm text-blue-300"
                    >
                      {typeof type === 'string' ? type : type.name}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Attachments */}
            {project.attachments && project.attachments.length > 0 && (
              <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
                <h2 className="text-xl font-semibold text-white mb-4">Attachments</h2>
                <div className="space-y-3">
                  {project.attachments.map((attachment, index) => {
                    const getFileIcon = (contentType: string) => {
                      if (contentType.includes('image')) return Image;
                      if (contentType.includes('pdf') || contentType.includes('document')) return FileText;
                      return Archive;
                    };
                    const FileIcon = getFileIcon(attachment.content_type);
                    
                    return (
                      <div key={index} className="flex items-center justify-between p-3 bg-white/5 border border-white/10 rounded-lg">
                        <div className="flex items-center gap-3">
                          <FileIcon className="w-5 h-5 text-gray-400" />
                          <div>
                            <p className="text-white font-medium">{attachment.filename}</p>
                            <p className="text-gray-400 text-sm">
                              {(attachment.size / 1024 / 1024).toFixed(2)} MB • {new Date(attachment.uploaded_at).toLocaleDateString()}
                            </p>
                          </div>
                        </div>
                        <a
                          href={attachment.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-2 px-3 py-1 bg-purple-600 hover:bg-purple-700 text-white text-sm rounded-lg transition-colors"
                        >
                          <Download className="w-4 h-4" />
                          Download
                        </a>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            {/* Project Info */}
            <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
              <h2 className="text-xl font-semibold text-white mb-4">Project Info</h2>
              <div className="space-y-4">
                <div>
                  <p className="text-gray-400 text-sm mb-1">Budget</p>
                  <div className="flex items-center gap-2">
                    <DollarSign className="w-4 h-4 text-green-400" />
                    <span className="text-white font-medium">
                      ${project.budget_amount?.toLocaleString()} {project.budget_currency}
                    </span>
                  </div>
                  {project.hourly_rate_min && project.hourly_rate_max && (
                    <p className="text-gray-400 text-sm mt-1">
                      Hourly: ${project.hourly_rate_min} - ${project.hourly_rate_max}/hr
                    </p>
                  )}
                </div>

                <div>
                  <p className="text-gray-400 text-sm mb-1">Budget Type</p>
                  <span className="text-white">
                    {typeof project.budget_type === 'string' ? project.budget_type : project.budget_type?.name || 'N/A'}
                  </span>
                </div>

                {project.category && (
                  <div>
                    <p className="text-gray-400 text-sm mb-1">Category</p>
                    <span className="text-white">{project.category.name}</span>
                  </div>
                )}

                {project.scope && (
                  <div>
                    <p className="text-gray-400 text-sm mb-1">Scope</p>
                    <span className="text-white">{project.scope.display_name || project.scope.name}</span>
                  </div>
                )}

                {project.experience_level && (
                  <div>
                    <p className="text-gray-400 text-sm mb-1">Experience Level</p>
                    <span className="text-white">{project.experience_level.name}</span>
                  </div>
                )}

                {project.deadline && (
                  <div>
                    <p className="text-gray-400 text-sm mb-1">Deadline</p>
                    <div className="flex items-center gap-2">
                      <Calendar className="w-4 h-4 text-yellow-400" />
                      <span className="text-white">{new Date(project.deadline).toLocaleDateString()}</span>
                    </div>
                  </div>
                )}

                <div>
                  <p className="text-gray-400 text-sm mb-1">Visibility</p>
                  <div className="flex items-center gap-2">
                    {project.visibility === 'public' ? (
                      <>
                        <Globe className="w-4 h-4 text-green-400" />
                        <span className="text-green-400">Public</span>
                      </>
                    ) : (
                      <>
                        <Lock className="w-4 h-4 text-gray-400" />
                        <span className="text-gray-400">Private</span>
                      </>
                    )}
                  </div>
                </div>

                {project.is_urgent && (
                  <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-3">
                    <div className="flex items-center gap-2">
                      <AlertCircle className="w-4 h-4 text-yellow-400" />
                      <span className="text-yellow-300 font-medium">Urgent Project</span>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Timeline */}
            <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
              <h2 className="text-xl font-semibold text-white mb-4">Timeline</h2>
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                  <div>
                    <p className="text-white text-sm">Created</p>
                    <p className="text-gray-400 text-xs">{new Date(project.created_at).toLocaleDateString()}</p>
                  </div>
                </div>
                
                {project.published_at && (
                  <div className="flex items-center gap-3">
                    <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
                    <div>
                      <p className="text-white text-sm">Published</p>
                      <p className="text-gray-400 text-xs">{new Date(project.published_at).toLocaleDateString()}</p>
                    </div>
                  </div>
                )}
                
                <div className="flex items-center gap-3">
                  <div className="w-2 h-2 bg-gray-400 rounded-full"></div>
                  <div>
                    <p className="text-white text-sm">Last Updated</p>
                    <p className="text-gray-400 text-xs">{new Date(project.updated_at).toLocaleDateString()}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Stats */}
            <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
              <h2 className="text-xl font-semibold text-white mb-4">Statistics</h2>
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Users className="w-4 h-4 text-blue-400" />
                    <span className="text-gray-400">Applicants</span>
                  </div>
                  <span className="text-white font-medium">{project.bid_count || 0}</span>
                </div>
                
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Eye className="w-4 h-4 text-purple-400" />
                    <span className="text-gray-400">Views</span>
                  </div>
                  <span className="text-white font-medium">-</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}