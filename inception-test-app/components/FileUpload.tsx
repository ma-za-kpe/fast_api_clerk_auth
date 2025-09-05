'use client';

import { useState, useRef } from 'react';
import { Upload, X, File, Image, FileText, Loader2, CheckCircle, AlertCircle } from 'lucide-react';

interface FileUploadProps {
  accept?: string;
  maxSize?: number; // in MB
  multiple?: boolean;
  onUpload: (files: File[]) => Promise<void>;
  uploadedFiles?: string[];
  label?: string;
  description?: string;
}

export default function FileUpload({
  accept = 'image/*,.pdf,.doc,.docx',
  maxSize = 10,
  multiple = true,
  onUpload,
  uploadedFiles = [],
  label = 'Upload Files',
  description = 'Drag and drop files here or click to browse',
}: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [uploadStatus, setUploadStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle');
  const [errorMessage, setErrorMessage] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const getFileIcon = (fileName: string) => {
    const extension = fileName.split('.').pop()?.toLowerCase();
    if (['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'].includes(extension || '')) {
      return <Image className="w-4 h-4" />;
    }
    if (['pdf', 'doc', 'docx', 'txt'].includes(extension || '')) {
      return <FileText className="w-4 h-4" />;
    }
    return <File className="w-4 h-4" />;
  };

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  const validateFiles = (files: File[]): { valid: File[]; errors: string[] } => {
    const valid: File[] = [];
    const errors: string[] = [];
    const maxSizeBytes = maxSize * 1024 * 1024;

    for (const file of files) {
      if (file.size > maxSizeBytes) {
        errors.push(`${file.name} exceeds ${maxSize}MB limit`);
      } else {
        valid.push(file);
      }
    }

    return { valid, errors };
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);

    const files = Array.from(e.dataTransfer.files);
    handleFiles(files);
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files);
      handleFiles(files);
    }
  };

  const handleFiles = (files: File[]) => {
    const { valid, errors } = validateFiles(files);
    
    if (errors.length > 0) {
      setErrorMessage(errors.join(', '));
      setUploadStatus('error');
      setTimeout(() => {
        setUploadStatus('idle');
        setErrorMessage('');
      }, 5000);
    }

    if (valid.length > 0) {
      if (multiple) {
        setSelectedFiles(prev => [...prev, ...valid]);
      } else {
        setSelectedFiles(valid.slice(0, 1));
      }
    }
  };

  const removeFile = (index: number) => {
    setSelectedFiles(prev => prev.filter((_, i) => i !== index));
  };

  const handleUpload = async () => {
    if (selectedFiles.length === 0) return;

    setUploading(true);
    setUploadStatus('uploading');

    try {
      await onUpload(selectedFiles);
      setUploadStatus('success');
      setSelectedFiles([]);
      setTimeout(() => {
        setUploadStatus('idle');
      }, 3000);
    } catch (error: any) {
      setUploadStatus('error');
      setErrorMessage(error.message || 'Upload failed');
      setTimeout(() => {
        setUploadStatus('idle');
        setErrorMessage('');
      }, 5000);
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-300 mb-2">
          {label}
        </label>
        
        {/* Drop Zone */}
        <div
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`relative border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-all ${
            isDragging
              ? 'border-purple-400 bg-purple-500/10'
              : 'border-white/20 bg-white/5 hover:bg-white/10'
          }`}
        >
          <input
            ref={fileInputRef}
            type="file"
            accept={accept}
            multiple={multiple}
            onChange={handleFileSelect}
            className="hidden"
          />
          
          <Upload className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <p className="text-white font-medium mb-1">{description}</p>
          <p className="text-gray-400 text-sm">
            {accept.replace(/\*/g, '').replace(/,/g, ', ')} • Max {maxSize}MB per file
          </p>
        </div>
      </div>

      {/* Selected Files */}
      {selectedFiles.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm font-medium text-gray-300">Selected Files</p>
          {selectedFiles.map((file, index) => (
            <div
              key={index}
              className="flex items-center justify-between p-3 bg-white/5 border border-white/10 rounded-lg"
            >
              <div className="flex items-center gap-3">
                <div className="text-gray-400">
                  {getFileIcon(file.name)}
                </div>
                <div>
                  <p className="text-white text-sm font-medium">{file.name}</p>
                  <p className="text-gray-400 text-xs">{formatFileSize(file.size)}</p>
                </div>
              </div>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  removeFile(index);
                }}
                className="p-1 text-red-400 hover:text-red-300"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          ))}
          
          <button
            onClick={handleUpload}
            disabled={uploading}
            className="w-full inline-flex items-center justify-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-800 text-white font-medium rounded-lg transition-colors"
          >
            {uploading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Uploading...
              </>
            ) : (
              <>
                <Upload className="w-4 h-4" />
                Upload {selectedFiles.length} File{selectedFiles.length !== 1 ? 's' : ''}
              </>
            )}
          </button>
        </div>
      )}

      {/* Uploaded Files */}
      {uploadedFiles.length > 0 && (
        <div className="space-y-2">
          <p className="text-sm font-medium text-gray-300">Uploaded Files</p>
          {uploadedFiles.map((file, index) => (
            <div
              key={index}
              className="flex items-center gap-3 p-3 bg-green-500/10 border border-green-500/20 rounded-lg"
            >
              <CheckCircle className="w-4 h-4 text-green-400" />
              <p className="text-green-300 text-sm">{file}</p>
            </div>
          ))}
        </div>
      )}

      {/* Status Messages */}
      {uploadStatus === 'success' && (
        <div className="flex items-center gap-2 p-3 bg-green-500/10 border border-green-500/20 rounded-lg">
          <CheckCircle className="w-4 h-4 text-green-400" />
          <p className="text-green-300 text-sm">Files uploaded successfully!</p>
        </div>
      )}

      {uploadStatus === 'error' && errorMessage && (
        <div className="flex items-center gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
          <AlertCircle className="w-4 h-4 text-red-400" />
          <p className="text-red-300 text-sm">{errorMessage}</p>
        </div>
      )}
    </div>
  );
}