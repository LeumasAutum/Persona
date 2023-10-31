from django.shortcuts import render, redirect
from .models import Company, Customer
from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse, HttpResponseRedirect
from django.core.files.storage import FileSystemStorage
from django.conf import settings
import os
from django.contrib import messages
from django.http import HttpResponse
from project.models import Project, Vulnerability
from django.contrib.auth.decorators import login_required
from project.models import Vulnerability
from django.db.models import Prefetch
from django.db.models import Count, Case, When, Value, IntegerField
from django.contrib.auth.decorators import user_passes_test
from django.urls import reverse
from django.db.models.functions import TruncMonth
from dateutil.rrule import rrule, MONTHLY

from datetime import datetime


def is_admin_user(user):
    if user.groups.filter(name='Admin').exists():
        return True
    else:
        next_url = reverse('/accounts/login')
        current_url = request.get_full_path()  # Get the current URL
        return HttpResponseRedirect(f'{next_url}?next={current_url}')

# Create your views here.

@login_required

def company(request):
    projects = Project.objects.all()
    vulnerabilities = Vulnerability.objects.all()

    # Create a dictionary to hold vulnerabilities grouped by project and sorted by severity
    project_vulnerabilities = {}

    for project in projects:
        project_vulnerabilities[project.id] = {
            'name': project.name,
            'vulnerabilities': sorted(
                [v for v in vulnerabilities if v.project_id == project.id],
                key=lambda v: (
                    v.vulnerabilityseverity != "Critical",
                    v.vulnerabilityseverity != "High",
                    v.vulnerabilityseverity != "Medium",
                    v.vulnerabilityseverity != "Low",
                    v.vulnerabilityseverity != "Informational",
                    v.vulnerabilityname
                )
            )
        }

    # Calculate vulnerability counts for each severity level
    for project_id, data in project_vulnerabilities.items():
        counts = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Informational": 0,
        }

        for vulnerability in data['vulnerabilities']:
            counts[vulnerability.vulnerabilityseverity] += 1

        data['vulnerability_counts'] = counts

    context = {
        'project_vulnerabilities': project_vulnerabilities.values(),
    }

    return render(request, "Company/Company.html", context)




from collections import defaultdict

@login_required
def vulnerability_summary(request):
    # Get the date range of your projects

    start_date = Project.objects.order_by('startdate').first().startdate

    end_date = Project.objects.order_by('startdate').last().startdate


    # Generate a list of all months in the range

    all_months = [dt.strftime('%Y-%m') for dt in rrule(MONTHLY, dtstart=start_date, until=end_date)]


    # Group projects by month and count them

    projects_per_month = Project.objects.annotate(month=TruncMonth('startdate')).values('month').annotate(count=Count('id')).order_by('month')


    # Convert queryset to dictionary for easy lookup

    projects_dict = {project['month'].strftime('%Y-%m'): project['count'] for project in projects_per_month}


    # Prepare data for the chart

    chart_data = {

        'months': all_months,

        'counts': [projects_dict.get(month, 0) for month in all_months],  # Use 0 for months with no projects

    }
    
    # Initialize a dictionary to store severity counts for all projects
    severity_counts = defaultdict(int)
    
    # Initialize a dictionary to store open vulnerabilities counts
    open_vulnerability_counts = defaultdict(int)
    
    # Fetch all projects
    projects = Project.objects.all()

    # List to store projects with open vulnerabilities
    projects_with_open_vulnerabilities = []

    # Loop through all projects
    for project in projects:
        # Fetch vulnerabilities for the current project
        vulnerabilities = Vulnerability.objects.filter(project=project)

        # Initialize a count for open vulnerabilities for the current project
        open_vulnerabilities_count = 0

        # Loop through all vulnerabilities
        for vulnerability in vulnerabilities:
            # Increment the appropriate counter based on the vulnerability's severity
            severity_counts[vulnerability.vulnerabilityseverity] += 1
            
            # Check if the vulnerability is open (status is "Vulnerable")
            if vulnerability.status == "Vulnerable":
                open_vulnerability_counts[vulnerability.vulnerabilityseverity] += 1
                open_vulnerabilities_count += 1

        # If the project has more than 5 open vulnerabilities, add it to the list
        if open_vulnerabilities_count > 3:
            projects_with_open_vulnerabilities.append({
                'name': project.name,
                'open_vulnerabilities_count': open_vulnerabilities_count,
            })

    # Sort the projects with open vulnerabilities by open_vulnerabilities_count in descending order
    projects_with_open_vulnerabilities.sort(key=lambda x: x['open_vulnerabilities_count'], reverse=True)

    # Calculate the total counts for each severity level
    total_severity_counts = {
        'Critical': severity_counts['Critical'],
        'High': severity_counts['High'],
        'Medium': severity_counts['Medium'],
        'Low': severity_counts['Low'],
        'Informational': severity_counts['Informational']
    }

    # Calculate the total counts for open vulnerabilities
    open_vulnerability_total_counts = {
        'Critical': open_vulnerability_counts['Critical'],
        'High': open_vulnerability_counts['High'],
        'Medium': open_vulnerability_counts['Medium'],
        'Low': open_vulnerability_counts['Low'],
        'Informational': open_vulnerability_counts['Informational']
    }

    return render(request, 'Company/vulnerability_summary.html', {
        'total_severity_counts': total_severity_counts,
        'open_vulnerability_total_counts': open_vulnerability_total_counts,
        'projects_with_open_vulnerabilities': projects_with_open_vulnerabilities,
        'chart_data': chart_data,
    })


@login_required
def open_vulnerabilities(request):
    # Fetch all projects
    projects = Project.objects.all()

    # Create a dictionary to hold vulnerabilities grouped by project and sorted by severity
    project_vulnerabilities = {}

    for project in projects:
        # Define the order of severity levels
        order = ['Critical', 'High', 'Medium', 'Low', 'Informational']

        # Create a conditional expression to map severity to an integer
        severity_ordering = Case(
            *[When(vulnerabilityseverity=severity, then=Value(order.index(severity))) for severity in order],
            default=Value(len(order)),
            output_field=IntegerField()
        )

        # Fetch open vulnerabilities for the current project and order by severity
        open_vulnerabilities = Vulnerability.objects.filter(
            project=project, status="Vulnerable"
        ).order_by(severity_ordering)

        if open_vulnerabilities.exists():
            project_vulnerabilities[project.id] = {
                'name': project.name,
                'vulnerabilities': open_vulnerabilities,
            }

    context = {
        'project_vulnerabilities': project_vulnerabilities.values(),
    }

    return render(request, "Company/openvulns.html", context)


@login_required
@user_passes_test(is_admin_user)
def delete(request):
    if request.method =='GET':
        companyid = request.GET['companyid']
        try:

            
            Company.objects.get(pk=companyid).delete()
            return HttpResponse(status=200)
            
            #responseData = {'status': 'Success'}

            #return JsonResponse(responseData)
        except ObjectDoesNotExist:
            messages.warning(request, "You don't have permission to delete a company.")
            return redirect('/')



@login_required
@user_passes_test(is_admin_user)
def edit(request):
    if request.method == 'GET':
        company = request.GET['company']

        try:
            company = Company.objects.get(pk=company)
            return render(request, "Company/EditCompany.html", {'company': company})
        except ObjectDoesNotExist:
            responseData = {'status': 'Fail to retrive data'}
            return JsonResponse(responseData)
    
    elif request.method =='POST':
        company = request.POST['company']
        name = request.POST['name']
        address = request.POST['address']
        # print(type(company))
        if company == "":
            responseData = {'status': 'Fail to update data'}
            return JsonResponse(responseData)
        else:
            try:
                companyobject = Company.objects.get(pk=company)
                companyobject.name = name
                companyobject.address = address
                companyobject.save()

                if 'image' in request.FILES:
                    upload = request.FILES['image']
                    path = os.path.join(settings.MEDIA_ROOT, 'company')
                    
                    fss = FileSystemStorage(location=path, base_url=path)
                    file = fss.save(upload.name, upload)
                    file_url = fss.url(file)

                    
                    companyobject.img = os.path.join('company', file_url)
                    companyobject.save()
                messages.info(request,'Company Updated successfully')
      
                return HttpResponseRedirect(request.path_info + "?company="+ company)
                #return HttpResponseRedirect(request.path_info + "?company="+ company)
                    

                

            except ObjectDoesNotExist:
                responseData = {'status': 'Fail to update data'}
                return JsonResponse(responseData)




@login_required
@user_passes_test(is_admin_user)
def add(request):
    if request.method == 'GET':
        return render(request, "Company/AddCompany.html")

    elif request.method =='POST':
        name = request.POST['name']
        address = request.POST['address']
        customer = Company(name=name,address=address)
        customer.save()
        if 'image' in request.FILES:
            upload = request.FILES['image']
            path = os.path.join(settings.MEDIA_ROOT, 'company')
                    
            fss = FileSystemStorage(location=path, base_url=path)
            file = fss.save(upload.name, upload)
            file_url = fss.url(file)
            customer.img =  os.path.join('company', file_url)
            customer.save()
        company = Company.objects.all()
        return render(request, "Company/Company.html", {'company': company})



@login_required
@user_passes_test(is_admin_user)
def customer(request):
    company = Company.objects.all()
    customer = Customer.objects.all()
    return render(request, "Customer/Customer.html", {'customer': customer, 'company':company})


@login_required
@user_passes_test(is_admin_user)
def customerdelete(request):
    if request.method =='GET':
        customerid = request.GET['customerid']
        try:
            Customer.objects.get(pk=customerid).delete()
            return HttpResponse(status=200)

        except ObjectDoesNotExist:
            messages.warning(request, "You don't have permission to delete a company.")
            return redirect('/')
        
        
@login_required
@user_passes_test(is_admin_user)
def customeredit(request):
    if request.method == 'GET':
        customer = request.GET['customer']

        try:
            customer = Customer.objects.get(pk=customer)
            company = Company.objects.all().values('name')
            return render(request, "Customer/EditCustomer.html", {'customer': customer, 'company': company})
        except ObjectDoesNotExist:
            responseData = {'status': 'Fail to retrive data'}
            return JsonResponse(responseData)

    elif request.method =='POST':

        company = request.POST['company']
        customername = request.POST['name']
        email = request.POST['email']
        number = request.POST['Number']
        customer = request.POST['customer']
        

        company = Company.objects.get(name=company)

        customerobject = Customer.objects.get(pk=customer)
        customerobject.company = company
        customerobject.name = customername
        customerobject.email = email 
        customerobject.phoneNumber = number
        customerobject.save()
        messages.info(request,'Customer Updated successfully')
        #return HttpResponseRedirect(request.path_info)
        return HttpResponseRedirect(request.path_info + "?customer="+ customer)


@login_required
@user_passes_test(is_admin_user)
def customeradd(request):
    if request.method == 'GET':
        company = Company.objects.all().values('name')
        return render(request, "Customer/AddCustomer.html", {'company': company})

    elif request.method =='POST':

        company = request.POST['company']
        customername = request.POST['name']
        email = request.POST['email']
        number = request.POST['Number']
        
        company = Company.objects.get(name=company)


        customeradd = Customer(company=company,name=customername, email=email, phoneNumber=number)
        customeradd.save()

        customer = Customer.objects.all()
        
        return render(request, "Customer/Customer.html", {'customer': customer})
    
# def vulnerability_summary(request):
#     # Fetch all projects
#     projects = Project.objects.all()

#     # Initialize counters for each severity level
#     severity_counts = {
#         'High': 0,
#         'Medium': 0,
#         'Low': 0,
#         'Other': 0
#     }

#     # Loop through all projects
#     for project in projects:
#         # Fetch vulnerabilities for the current project
#         vulnerabilities = Vulnerability.objects.filter(project=project)

#         # Loop through all vulnerabilities
#         for vulnerability in vulnerabilities:
#             # Increment the appropriate counter based on the vulnerability's severity
#             if vulnerability.vulnerabilityseverity in severity_counts:
#                 severity_counts[vulnerability.vulnerabilityseverity] += 1
#             else:
#                 severity_counts['Other'] += 1
#             print(severity_counts)

#     return render(request, 'Customer/Customer.html', {
#         'severity_counts': severity_counts,
#     })   
    
    
    
    