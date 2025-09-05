# Ampersand Platform - How It Works

## User Journey & Success Paths

### 🎯 Overview
The Ampersand Platform connects companies (Clients) with vetted developers through a managed service model. Each user type has a specific journey to success.

---

## 1. CLIENT Journey (Company Looking for Developers)

### Step 1: Sign Up as Client
```json
POST /api/v1/auth/signup
{
  "email": "john@company.com",
  "password": "SecurePass123!",
  "first_name": "John",
  "last_name": "Doe",
  "user_type": "client"  // ← This determines their role
}
```
**What Happens:**
- User account created in Clerk
- UserTypeProfile created with type = "CLIENT"
- User receives response with `user_type: "client"`

### Step 2: Create Company Profile
```json
POST /api/v1/clients/company
{
  "name": "TechCorp Inc",
  "size_id": 2,  // Medium company
  "business_type_id": 1,  // Technology
  "location_country": "USA",
  "city": "San Francisco",
  "website": "https://techcorp.com",
  "description": "We build amazing software"
}
```
**Access Control:** ✅ Only users with `user_type: "client"` can create companies

### Step 3: Create a Project
```json
POST /api/v1/projects
{
  "title": "E-commerce Platform",
  "description": "Build our online store",
  "budget_type": "fixed",
  "budget_amount": 50000,
  "tech_stack": ["React", "Node.js", "PostgreSQL"],
  "experience_level": "senior"
}
```

### Step 4: Review Developer Bids
```json
GET /api/v1/projects/{project_id}/bids
```
- See list of developers who bid
- Review their profiles, ratings, hourly rates
- Accept the best candidate

### Step 5: Manage Project
- Track milestones
- Approve deliverables
- Process payments
- Leave reviews

**Success:** Project completed, developer paid, both parties leave reviews

---

## 2. DEVELOPER Journey (Squad Member)

### Step 1: Sign Up as Developer
```json
POST /api/v1/auth/signup
{
  "email": "jane@email.com",
  "password": "DevPass456!",
  "first_name": "Jane",
  "last_name": "Smith",
  "user_type": "developer"  // ← This determines their role
}
```
**What Happens:**
- User account created in Clerk
- UserTypeProfile created with type = "DEVELOPER"
- User receives response with `user_type: "developer"`

### Step 2: Complete Developer Profile
```json
POST /api/v1/developers/profile
{
  "primary_role": "Full Stack Developer",
  "years_experience": 5,
  "tech_stack": ["React", "Node.js", "Python", "AWS"],
  "github_username": "janesmith",
  "hourly_rate": 75.00,
  "bio": "Experienced full-stack developer...",
  "country": "Canada",
  "availability_status": "available"
}
```
**Status:** Profile pending vetting

### Step 3: Get Vetted by Engineering Manager
- Engineering Manager reviews profile
- Checks GitHub, portfolio
- Approves or requests changes
- **Status changes:** `pending` → `approved`

### Step 4: Browse & Bid on Projects
```json
GET /api/v1/projects/available
// Shows projects matching developer's skills

POST /api/v1/projects/{project_id}/bid
{
  "proposed_rate": 75.00,
  "estimated_duration": "3 months",
  "cover_letter": "I'm perfect for this project because..."
}
```

### Step 5: Work on Accepted Projects
- Receive task assignments
- Log time worked
- Submit deliverables
- Get paid bi-weekly

**Success:** Complete projects, earn money, build reputation, earn tokens

---

## 3. ENGINEERING MANAGER Journey

### Step 1: Sign Up as Engineering Manager
```json
POST /api/v1/auth/signup
{
  "email": "mike@ampersand.com",
  "password": "Manager789!",
  "user_type": "engineering_manager"
}
```

### Step 2: Review Pending Developers
```json
GET /api/v1/developers/pending-vetting

POST /api/v1/developers/{developer_id}/vet
{
  "vetting_status": "approved",
  "vetting_notes": "Strong portfolio, verified skills"
}
```

### Step 3: Match Developers to Projects
- Review project requirements
- Find best-fit developers
- Assign or approve bids

**Success:** High-quality developer pool, successful project matches

---

## 4. DELIVERY MANAGER Journey

### Step 1: Sign Up as Delivery Manager
```json
POST /api/v1/auth/signup
{
  "user_type": "delivery_manager"
}
```

### Step 2: Manage Projects
- Create project plans
- Set milestones
- Monitor progress
- Coordinate between client and developers

### Step 3: Quality Control
- Review completed tasks
- Approve for payment
- Handle issues

**Success:** Projects delivered on time, within budget

---

## 5. TECH LEAD Journey

### Step 1: Sign Up as Tech Lead
```json
POST /api/v1/auth/signup
{
  "email": "sarah@ampersand.com",
  "password": "TechLead123!",
  "user_type": "tech_lead"
}
```

### Step 2: Set Technical Standards
- Define coding standards and best practices
- Create technical architecture guidelines
- Review and approve tech stack choices for projects
- Establish code review processes

### Step 3: Provide Technical Leadership
```json
GET /api/v1/projects/technical-review
POST /api/v1/projects/{project_id}/technical-approval
{
  "approved": true,
  "technical_notes": "Architecture looks solid, recommended React/Node.js stack"
}
```

### Step 4: Mentor Developers
- Review developer technical assessments
- Provide technical guidance on complex implementations
- Conduct technical interviews for senior developers
- Create technical learning paths

### Step 5: Quality Assurance
- Perform code architecture reviews
- Ensure technical debt management
- Monitor performance metrics
- Approve technical milestones

**Success:** High-quality technical implementations, reduced technical debt, strong developer growth

---

## 6. QA LEAD Journey

### Step 1: Sign Up as QA Lead
```json
POST /api/v1/auth/signup
{
  "email": "alex@ampersand.com",
  "password": "QALead456!",
  "user_type": "qa_lead"
}
```

### Step 2: Establish QA Standards
- Define testing requirements for projects
- Create quality gates and acceptance criteria
- Establish bug severity and priority guidelines
- Set up automated testing standards

### Step 3: Review Project Quality
```json
GET /api/v1/projects/quality-review
POST /api/v1/projects/{project_id}/quality-approval
{
  "quality_status": "passed",
  "test_coverage": 85,
  "bugs_found": 3,
  "quality_notes": "All critical tests pass, minor UI issues resolved"
}
```

### Step 4: Manage Testing Process
- Assign QA resources to projects
- Review test plans and test cases
- Oversee user acceptance testing (UAT)
- Coordinate with developers on bug fixes

### Step 5: Final Quality Gate
- Approve deliverables before client handoff
- Sign off on production releases
- Monitor post-deployment quality metrics
- Generate quality reports

**Success:** High-quality deliverables, minimal production bugs, strong client satisfaction

---

## 7. ADMIN Journey

### Step 1: Sign Up as Admin
```json
POST /api/v1/auth/signup
{
  "email": "admin@ampersand.com",
  "password": "Admin789!",
  "user_type": "admin"
}
```

### Step 2: Platform Management
- Monitor platform health and performance
- Manage user accounts and permissions
- Configure system settings and parameters
- Handle platform-wide announcements

### Step 3: User Management
```json
GET /api/v1/admin/users
POST /api/v1/admin/users/{user_id}/suspend
{
  "reason": "Policy violation",
  "duration": "30 days"
}
```

### Step 4: Content Moderation
- Review and moderate project postings
- Handle disputes between clients and developers
- Manage platform policies and compliance
- Monitor for fraudulent activities

### Step 5: Platform Analytics
- Generate platform performance reports
- Monitor revenue and transaction metrics
- Analyze user engagement and retention
- Create business intelligence dashboards

**Success:** Smooth platform operations, high user satisfaction, platform growth

---

## User Type Enforcement Flow

### How The System Knows Who Can Do What:

1. **During Sign Up:**
   - User selects their type (client/developer/manager)
   - System creates UserTypeProfile record
   - Type stored in database

2. **During Sign In:**
   ```json
   POST /api/v1/auth/signin
   Response includes:
   {
     "user": {
       "id": "user_123",
       "email": "user@example.com",
       "user_type": "client"  // ← Frontend uses this
     }
   }
   ```

3. **On Every Request:**
   - Frontend includes Bearer token
   - Backend validates token
   - Backend checks user_type from database
   - Enforces access control

4. **Access Control Examples:**

   | Endpoint | Client | Developer | Delivery Manager | Engineering Manager | Tech Lead | QA Lead | Admin |
   |----------|--------|-----------|------------------|-------------------|-----------|---------|--------|
   | Create Company | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
   | Create Project | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
   | Bid on Project | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
   | Vet Developer | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ |
   | Approve Milestone | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |
   | Technical Approval | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
   | Quality Approval | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
   | User Management | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
   | Platform Analytics | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |

---

## Authentication Flow

### 1. Initial Authentication
```javascript
// Frontend
const response = await fetch('/api/v1/auth/signin', {
  method: 'POST',
  body: JSON.stringify({ clerk_token: clerkSessionToken })
});

const data = await response.json();
// data.user.user_type tells frontend what UI to show
```

### 2. Frontend Routing Based on User Type
```javascript
switch(user.user_type) {
  case 'client':
    redirect('/client-dashboard');
    break;
  case 'developer':
    redirect('/developer-dashboard');
    break;
  case 'delivery_manager':
    redirect('/projects/manage');
    break;
}
```

### 3. Backend Enforcement
```python
# Company creation endpoint
async def create_company(user_id: str, ...):
    # This will throw error if user is not CLIENT type
    await user_type_service.verify_user_type(db, user_id, UserType.CLIENT)
    # Only proceeds if user is CLIENT
    company = await company_service.create_company(...)
```

---

## Token & Gamification System

### Developers Earn Tokens For:
- **First Bid Submitted:** 2 tokens
- **First Milestone Completed:** 5 tokens
- **On-Time Delivery:** 1 token per task
- **5-Star Rating:** 3 tokens
- **Global Collaborator Achievement:** 20 tokens (worked with 5+ countries)

### Token Uses (Future):
- Boost bid visibility
- Access premium projects
- Platform rewards/swag
- Priority support

---

## Database Structure

### User Type Tracking:
```sql
-- Every user has exactly one type
user_type_profiles
├── user_id (unique)
├── user_type (client/developer/manager)
└── verified_at (when approved)

-- Clients have companies
companies
├── owner_id (links to user)
└── company details...

-- Developers have profiles
developer_profiles
├── user_id (links to user)
├── vetting_status (pending/approved/rejected)
└── professional details...
```

---

## API Response Examples

### Sign In Response (Shows User Type):
```json
{
  "access_token": "...",
  "user": {
    "id": "user_123",
    "email": "john@company.com",
    "first_name": "John",
    "last_name": "Doe",
    "user_type": "client"  // ← Frontend uses this to show correct UI
  }
}
```

### GET /api/v1/auth/me Response:
```json
{
  "user_id": "user_123",
  "email": "jane@email.com",
  "user_type": "developer",  // ← Determines available actions
  "first_name": "Jane",
  "last_name": "Smith"
}
```

---

## Error Handling

### When Wrong User Type Tries Restricted Action:
```json
// Developer tries to create company
POST /api/v1/clients/company
Response: 403 Forbidden
{
  "detail": "This action requires client access"
}
```

### When Developer Not Vetted Yet:
```json
// Pending developer tries to bid
POST /api/v1/projects/123/bid
Response: 403 Forbidden
{
  "detail": "Your profile must be approved before bidding"
}
```

---

## Testing the Flow

### 1. Test Client Flow:
```bash
# Sign up as client
curl -X POST http://localhost:8000/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"client@test.com", "password":"Test123!", "user_type":"client"}'

# Create company (with auth token)
curl -X POST http://localhost:8000/api/v1/clients/company \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test Company", "size_id":1}'
```

### 2. Test Developer Flow:
```bash
# Sign up as developer
curl -X POST http://localhost:8000/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"email":"dev@test.com", "password":"Test123!", "user_type":"developer"}'

# Try to create company (should fail)
curl -X POST http://localhost:8000/api/v1/clients/company \
  -H "Authorization: Bearer DEV_TOKEN" \
  -d '{"name":"Test Company"}'
# Response: 403 Forbidden - "This action requires client access"
```

---

## Summary

The platform ensures proper access control through:

1. **User Type Assignment at Signup** - Each user declares their role
2. **Database Tracking** - UserTypeProfile table maintains user types
3. **API Response Inclusion** - All auth endpoints return user_type
4. **Backend Enforcement** - Services verify user type before actions
5. **Frontend Routing** - UI adapts based on user_type

This creates a secure, role-based system where:
- **Clients** can only create companies and projects
- **Developers** can only create developer profiles and bid
- **Managers** have their specific oversight capabilities
- **Everyone** stays in their lane, ensuring platform integrity