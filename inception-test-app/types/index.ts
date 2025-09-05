export type UserType = 
  | 'client' 
  | 'developer' 
  | 'engineering_manager' 
  | 'delivery_manager' 
  | 'tech_lead' 
  | 'qa_lead' 
  | 'admin';

export interface User {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  user_type: UserType;
  created_at: string;
  updated_at: string;
}

export interface Company {
  id: string;
  name: string;
  owner_id: string;
  size_id?: number;
  business_type_id?: number;
  location_country?: string;
  location_state?: string;
  city?: string;
  website?: string;
  description?: string;
  logo_url?: string;
  is_verified: boolean;
  created_at: string;
  updated_at: string;
}

export interface DeveloperProfile {
  id: string;
  user_id: string;
  primary_role: string;
  years_experience: number;
  tech_stack: string[];
  github_username?: string;
  linkedin_url?: string;
  portfolio_url?: string;
  hourly_rate?: number;
  bio?: string;
  country?: string;
  availability_status: 'available' | 'busy' | 'not_available';
  vetting_status: 'pending' | 'approved' | 'rejected';
  vetting_notes?: string;
  vetted_by?: string;
  vetted_at?: string;
  created_at: string;
  updated_at: string;
}

export interface Project {
  id: string;
  title: string;
  code_name: string;
  description: string;
  status: string;
  category?: any;
  scope?: any;
  experience_level?: any;
  budget_type: any;
  budget_amount?: number;
  budget_currency?: string;
  hourly_rate_min?: number;
  hourly_rate_max?: number;
  tech_stacks?: any[];
  tech_stack?: string[];
  project_types?: any[];
  client_id: string;
  company_id?: number;
  attachments?: any[];
  is_featured: boolean;
  is_urgent: boolean;
  visibility: string;
  created_at: string;
  updated_at: string;
  published_at?: string;
  deadline?: string;
  bid_count?: number;
}

export interface Bid {
  id: string;
  project_id: string;
  developer_id: string;
  proposed_rate: number;
  estimated_duration: string;
  cover_letter: string;
  status: 'pending' | 'accepted' | 'rejected';
  created_at: string;
  updated_at: string;
}

export interface Milestone {
  id: string;
  project_id: string;
  title: string;
  description: string;
  amount: number;
  due_date: string;
  status: 'pending' | 'in_progress' | 'completed' | 'approved';
  created_at: string;
  updated_at: string;
}

export interface ReferenceData {
  id: number;
  name: string;
  description?: string;
  is_active: boolean;
}

export interface CompanySize extends ReferenceData {
  employee_range?: string;
}

export interface BusinessType extends ReferenceData {
  category?: string;
}

export interface TechStack extends ReferenceData {
  category?: string;
  popularity_score?: number;
}