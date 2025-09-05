'use client';

import { useAuth } from '@clerk/nextjs';
import { useCallback } from 'react';
import api from '@/lib/api';

export function useApi() {
  const { getToken } = useAuth();

  const callApi = useCallback(
    async (
      endpoint: string,
      options: RequestInit = {}
    ) => {
      const token = await getToken();
      
      if (!token) {
        throw new Error('Not authenticated');
      }

      const response = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1'}${endpoint}`,
        {
          ...options,
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
            ...options.headers,
          },
        }
      );

      if (!response.ok) {
        const error = await response.json().catch(() => ({
          detail: 'An error occurred',
        }));
        console.error('API Error:', error);
        
        // Handle validation errors (422) with detailed messages
        if (response.status === 422 && error.detail && Array.isArray(error.detail)) {
          const validationErrors = error.detail.map((err: any) => {
            const field = err.loc ? err.loc[err.loc.length - 1] : 'unknown';
            return `${field}: ${err.msg}`;
          }).join('; ');
          throw new Error(`Validation failed: ${validationErrors}`);
        }
        
        throw new Error(error.detail || error.message || JSON.stringify(error) || `API Error: ${response.statusText}`);
      }

      return response.json();
    },
    [getToken]
  );

  return {
    callApi,
    auth: {
      syncWithBackend: async () => {
        const token = await getToken();
        if (!token) throw new Error('No Clerk token available');
        
        return callApi('/auth/signin', {
          method: 'POST',
          body: JSON.stringify({ clerk_token: token }),
        });
      },
      signup: (data: any) => callApi('/auth/signup', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
      me: () => callApi('/auth/me'),
    },
    companies: {
      create: (data: any) => callApi('/companies/company', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
      get: () => callApi('/companies/company'),
      update: (id: string, data: any) => callApi(`/companies/company/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
    },
    developers: {
      create: (data: any) => callApi('/developers/profile', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
      getProfile: () => callApi('/developers/profile'),
      updateProfile: (data: any) => callApi('/developers/profile', {
        method: 'PATCH',
        body: JSON.stringify(data),
      }),
      getPendingVetting: () => callApi('/developers/pending-vetting'),
      vetDeveloper: (developerId: string, data: any) => callApi(`/developers/${developerId}/vet`, {
        method: 'POST',
        body: JSON.stringify(data),
      }),
    },
    projects: {
      create: (data: any) => callApi('/projects', {
        method: 'POST',
        body: JSON.stringify(data),
      }),
      list: (params?: any) => {
        const queryString = params ? '?' + new URLSearchParams(params).toString() : '';
        return callApi(`/projects${queryString}`);
      },
      get: (projectId: string) => callApi(`/projects/${projectId}`),
      update: (projectId: string, data: any) => callApi(`/projects/${projectId}`, {
        method: 'PUT',
        body: JSON.stringify(data),
      }),
      delete: (projectId: string) => callApi(`/projects/${projectId}`, {
        method: 'DELETE',
      }),
      publish: (projectId: string) => callApi(`/projects/${projectId}/publish`, {
        method: 'POST',
      }),
      uploadAttachment: async (projectId: string, file: File, attachmentType: string = 'Other') => {
        const token = await getToken();
        if (!token) throw new Error('Not authenticated');
        
        const formData = new FormData();
        // Backend requires attachment_type field
        formData.append('attachment_type', attachmentType);
        // Backend expects 'files' field, not 'file'
        formData.append('files', file);
        
        const response = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1'}/projects/${projectId}/attachments`,
          {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              // Don't set Content-Type - let browser set it with boundary
            },
            body: formData,
          }
        );
        
        if (!response.ok) {
          const error = await response.json().catch(() => ({ detail: 'Upload failed' }));
          throw new Error(error.detail || 'Upload failed');
        }
        
        return response.json();
      },
      getAttachments: async (projectId: string, attachmentType?: string) => {
        const token = await getToken();
        if (!token) throw new Error('Not authenticated');
        
        const params = attachmentType ? `?attachment_type=${encodeURIComponent(attachmentType)}` : '';
        const response = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1'}/projects/${projectId}/attachments${params}`,
          {
            headers: {
              'Authorization': `Bearer ${token}`,
            },
          }
        );
        
        if (!response.ok) {
          const error = await response.json().catch(() => ({ detail: 'Failed to get attachments' }));
          throw new Error(error.detail || 'Failed to get attachments');
        }
        
        return response.json();
      },
      submitBid: (projectId: string, data: any) => callApi(`/projects/${projectId}/bid`, {
        method: 'POST',
        body: JSON.stringify(data),
      }),
      getBids: (projectId: string) => callApi(`/projects/${projectId}/bids`),
      acceptBid: (projectId: string, bidId: string) => callApi(`/projects/${projectId}/bids/${bidId}/accept`, {
        method: 'POST',
      }),
      getAvailable: () => callApi('/projects/available'),
    },
    reference: {
      getDeveloperRoles: () => callApi('/admin/reference/developer-roles'),
      getTechStacks: () => callApi('/admin/reference/tech-stacks'),
      getCompanySizes: () => callApi('/admin/reference/company-sizes'),
      getBusinessTypes: () => callApi('/admin/reference/business-types'),
      getProjectTypes: () => callApi('/admin/reference/project-types'),
      getProjectCategories: () => callApi('/admin/reference/project-categories'),
      getProjectScopes: () => callApi('/admin/reference/project-scopes'),
      getExperienceLevels: () => callApi('/admin/reference/experience-levels'),
      getBudgetTypes: () => callApi('/admin/reference/budget-types'),
    },
    admin: {
      getUsers: (params?: any) => {
        const queryString = params ? '?' + new URLSearchParams(params).toString() : '';
        return callApi(`/admin/users${queryString}`);
      },
      getAnalytics: () => callApi('/admin/analytics'),
      getAuditLogs: (params?: any) => {
        const queryString = params ? '?' + new URLSearchParams(params).toString() : '';
        return callApi(`/admin/audit-logs${queryString}`);
      },
      populateReferenceData: () => callApi('/admin/reference/populate-all', {
        method: 'POST',
      }),
    },
  };
}

export default useApi;