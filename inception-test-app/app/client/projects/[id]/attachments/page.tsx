'use client';

import { useEffect, useState, useRef } from 'react';
import { useUser, useClerk } from '@clerk/nextjs';
import { useRouter, useParams } from 'next/navigation';
import useApi from '@/hooks/useApi';
import { 
  Building2, ArrowLeft, Upload, Download, Trash2, 
  FileText, Image, Archive, Loader2, AlertCircle,
  Plus, X
} from 'lucide-react';
import { Project } from '@/types';

interface Attachment {
  filename: string;
  url: string;
  size: number;
  content_type: string;
  attachment_type: string;
  uploader_id: string;
  uploaded_at: string;
}

const attachmentTypes = [
  { value: 'High Fidelity Mockups', label: 'High Fidelity Mockups', icon: Image },
  { value: 'Product Requirements Document', label: 'Product Requirements', icon: FileText },
  { value: 'Functional Specification Document', label: 'Functional Spec', icon: FileText },
  { value: 'Invoice', label: 'Invoice', icon: FileText },
  { value: 'Report', label: 'Report', icon: FileText },
  { value: 'User Stories / Use Cases', label: 'User Stories', icon: FileText },
  { value: 'User Journey / Flow Diagrams', label: 'User Journey', icon: FileText },
  { value: 'Architecture Diagram', label: 'Architecture', icon: FileText },
  { value: 'Other', label: 'Other', icon: Archive },
];

export default function ProjectAttachmentsPage() {
  const { isLoaded, isSignedIn } = useUser();
  const { signOut } = useClerk();
  const router = useRouter();
  const params = useParams();
  const api = useApi();
  
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [project, setProject] = useState<Project | null>(null);
  const [attachments, setAttachments] = useState<Attachment[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [dragActive, setDragActive] = useState(false);
  const [selectedType, setSelectedType] = useState<string>('Other');
  const [filterType, setFilterType] = useState<string>('');
  
  const fileInputRef = useRef<HTMLInputElement>(null);
  const projectId = params.id as string;

  const allowedTypes = ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain', 'image/png', 'image/jpeg', 'image/jpg', 'application/zip'];
  const maxSize = 10 * 1024 * 1024; // 10MB

  useEffect(() => {
    if (isLoaded && isSignedIn && projectId) {
      loadData();
    }
  }, [isLoaded, isSignedIn, projectId]);

  const loadData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Load project data
      const projectData = await api.projects.get(projectId);
      setProject(projectData);
      
      // Load attachments using the new endpoint
      try {
        const attachmentData = await api.projects.getAttachments(projectId, filterType || undefined);
        setAttachments(attachmentData);
      } catch (attachmentError: any) {
        console.log('Could not load attachments separately, falling back to project data');
        // Fallback to project data if new endpoint not available
        if (projectData.attachments) {
          setAttachments(projectData.attachments);
        }
      }
    } catch (error: any) {
      console.error('Failed to load project data:', error);
      setError(error.message || 'Failed to load project data');
    } finally {
      setLoading(false);
    }
  };

  const handleFileUpload = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    
    try {
      setUploading(true);
      let successCount = 0;
      let failCount = 0;
      
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        
        // Validate file type
        if (!allowedTypes.includes(file.type)) {
          alert(`${file.name}: File type not supported. Allowed: PDF, DOC, DOCX, TXT, PNG, JPG, JPEG, ZIP`);
          failCount++;
          continue;
        }
        
        // Validate file size
        if (file.size > maxSize) {
          alert(`${file.name}: File too large. Maximum size is 10MB`);
          failCount++;
          continue;
        }
        
        try {
          const response = await api.projects.uploadAttachment(projectId, file, selectedType);
          console.log(`Successfully uploaded ${file.name} as ${selectedType}:`, response);
          successCount++;
          
          // Add the new attachment to the list immediately
          if (response.files && response.files.length > 0) {
            const newAttachment = response.files[0];
            setAttachments(prev => [...prev, newAttachment]);
          }
        } catch (error: any) {
          console.error(`Failed to upload ${file.name}:`, error);
          alert(`Failed to upload ${file.name}: ${error.message}`);
          failCount++;
        }
      }
      
      // Show summary
      if (successCount > 0) {
        console.log(`Successfully uploaded ${successCount} file(s)`);
      }
      if (failCount > 0) {
        console.log(`Failed to upload ${failCount} file(s)`);
      }
      
      // Reset file input
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
      
      // Don't reload if we already added attachments to the list
      // This avoids CORS errors and unnecessary API calls
      console.log(`Upload complete. ${successCount} files added to the list.`);
    } catch (error: any) {
      console.error('Upload error:', error);
      alert('An error occurred during upload. Please try again.');
    } finally {
      setUploading(false);
    }
  };


  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleFileUpload(e.dataTransfer.files);
    }
  };

  const getFileIcon = (contentType: string) => {
    if (contentType.includes('image')) return Image;
    if (contentType.includes('pdf') || contentType.includes('document') || contentType.includes('text')) return FileText;
    return Archive;
  };

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
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
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
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
            <h1 className="text-3xl font-bold text-white">Project Files</h1>
            <p className="text-gray-300">{project?.title}</p>
          </div>
        </div>

        {/* Upload Area */}
        <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6 mb-8">
          <h2 className="text-xl font-semibold text-white mb-4">Upload Files</h2>
          
          {/* Attachment Type Selector */}
          <div className="mb-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Select Attachment Type
            </label>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {attachmentTypes.map((type) => {
                const Icon = type.icon;
                return (
                  <button
                    key={type.value}
                    type="button"
                    onClick={() => setSelectedType(type.value)}
                    className={`flex items-center gap-2 px-3 py-2 rounded-lg border transition-colors ${
                      selectedType === type.value
                        ? 'bg-purple-600/20 border-purple-400 text-purple-300'
                        : 'bg-white/5 border-white/10 text-gray-300 hover:bg-white/10'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span className="text-sm">{type.label}</span>
                  </button>
                );
              })}
            </div>
          </div>
          
          <div
            className={`border-2 border-dashed rounded-xl p-8 text-center transition-all ${
              dragActive 
                ? 'border-purple-400 bg-purple-400/10' 
                : 'border-white/20 hover:border-white/30'
            }`}
            onDragEnter={handleDrag}
            onDragLeave={handleDrag}
            onDragOver={handleDrag}
            onDrop={handleDrop}
          >
            <Upload className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-white mb-2">
              {dragActive ? 'Drop files here' : 'Upload project files'}
            </h3>
            <p className="text-gray-400 mb-4">
              Drag and drop files here, or click to select files
            </p>
            <p className="text-gray-500 text-sm mb-6">
              Supported: PDF, DOC, DOCX, TXT, PNG, JPG, JPEG, ZIP (Max 10MB each)
            </p>
            
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".pdf,.doc,.docx,.txt,.png,.jpg,.jpeg,.zip"
              onChange={(e) => handleFileUpload(e.target.files)}
              className="hidden"
            />
            
            <button
              onClick={() => fileInputRef.current?.click()}
              disabled={uploading}
              className="inline-flex items-center gap-2 px-6 py-3 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-800 text-white font-medium rounded-lg transition-colors"
            >
              {uploading ? (
                <Loader2 className="w-5 h-5 animate-spin" />
              ) : (
                <Plus className="w-5 h-5" />
              )}
              {uploading ? 'Uploading...' : 'Select Files'}
            </button>
          </div>
        </div>

        {/* Files List */}
        <div className="bg-black/30 backdrop-blur-xl border border-white/10 rounded-xl p-6">
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-xl font-semibold text-white">Uploaded Files ({attachments.length})</h2>
            
            {/* Filter by Type */}
            <div className="flex items-center gap-2">
              <label className="text-sm text-gray-400">Filter:</label>
              <select
                value={filterType}
                onChange={(e) => {
                  setFilterType(e.target.value);
                  loadData(); // Reload with filter
                }}
                className="px-3 py-1 bg-white/10 border border-white/20 rounded-lg text-white text-sm [&>option]:bg-gray-900 [&>option]:text-white"
              >
                <option value="">All Types</option>
                {attachmentTypes.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
          
          {attachments.length === 0 ? (
            <div className="text-center py-12">
              <FileText className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <p className="text-gray-400 mb-2">No files uploaded yet</p>
              <p className="text-gray-500 text-sm">Upload files to share with developers</p>
            </div>
          ) : (
            <div className="grid gap-4">
              {attachments.map((attachment, index) => {
                const FileIcon = getFileIcon(attachment.content_type);
                
                return (
                  <div
                    key={`${attachment.filename}-${index}`}
                    className="flex items-center justify-between p-4 bg-white/5 border border-white/10 rounded-lg hover:bg-white/10 transition-colors"
                  >
                    <div className="flex items-center gap-4">
                      <div className="w-10 h-10 bg-purple-500/20 rounded-lg flex items-center justify-center">
                        <FileIcon className="w-5 h-5 text-purple-400" />
                      </div>
                      <div>
                        <h3 className="text-white font-medium">{attachment.filename}</h3>
                        <div className="flex items-center gap-3 text-sm text-gray-400">
                          <span>{formatFileSize(attachment.size)}</span>
                          <span>•</span>
                          <span>{new Date(attachment.uploaded_at).toLocaleDateString()}</span>
                          <span>•</span>
                          <span className="px-2 py-1 bg-purple-500/20 text-purple-300 rounded text-xs">
                            {attachment.attachment_type || 'Other'}
                          </span>
                          <span className="px-2 py-1 bg-gray-500/20 rounded text-xs">
                            {attachment.content_type.split('/')[1].toUpperCase()}
                          </span>
                        </div>
                      </div>
                    </div>
                    
                    <a
                      href={attachment.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors"
                    >
                      <Download className="w-4 h-4" />
                      Download
                    </a>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* File Guidelines */}
        <div className="mt-6 bg-blue-500/10 border border-blue-500/20 rounded-xl p-4">
          <h3 className="text-blue-300 font-medium mb-2">File Upload Guidelines</h3>
          <ul className="text-blue-200 text-sm space-y-1">
            <li>• Maximum file size: 10MB per file</li>
            <li>• Supported formats: PDF, DOC, DOCX, TXT, PNG, JPG, JPEG, ZIP</li>
            <li>• Files are automatically shared with developers when they apply</li>
            <li>• Only project owners can upload and delete files</li>
          </ul>
        </div>
      </div>
    </div>
  );
}