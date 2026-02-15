import os
import json

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_from_directory, abort
from sqlalchemy import func, desc
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone

from database import init_db, get_session, Session
from models import Incident, FetchLog, ThreatPerson, ThreatOrganization, IOCIndicator, UploadedDocument
from rss_parser import fetch_all_feeds
from mitre_data import get_technique_name
from config import (
    SECRET_KEY, SEVERITY_LEVELS, ATTACK_TYPE_KEYWORDS,
    SECTOR_KEYWORDS, INCIDENTS_PER_PAGE, RSS_FEEDS, BASE_DIR,
    TWITTER_ENABLED, LINKEDIN_ENABLED,
    VIRUSTOTAL_ENABLED, ABUSEIPDB_ENABLED,
    IOC_FEEDS_ENABLED, IOC_PER_PAGE, IOC_THREAT_LEVELS,
    IOC_THREAT_LEVEL_LABELS, IOC_TYPE_LABELS,
    UPLOAD_DIR, ALLOWED_EXTENSIONS, MAX_UPLOAD_SIZE_MB, DOCS_PER_PAGE,
)
from ioc_extractor import format_iocs_display


def create_app():
    app = Flask(__name__)
    app.secret_key = SECRET_KEY

    @app.teardown_appcontext
    def shutdown_session(exception=None):
        Session.remove()

    # Severity CSS class mapping
    severity_css = {
        'Критичний': 'critical',
        'Високий': 'high',
        'Середній': 'medium',
        'Низький': 'low',
    }

    @app.template_filter('severity_class')
    def severity_class_filter(severity):
        return severity_css.get(severity, 'low')

    @app.template_filter('parse_images')
    def parse_images_filter(images_json):
        """Parse JSON image paths list, return relative paths for URL generation."""
        if not images_json:
            return []
        try:
            paths = json.loads(images_json)
            images_dir = os.path.join(BASE_DIR, 'data', 'images')
            result = []
            for p in paths:
                if os.path.isfile(p):
                    # Convert absolute path to relative (for URL)
                    rel = os.path.relpath(p, images_dir).replace('\\', '/')
                    result.append(rel)
            return result
        except (json.JSONDecodeError, TypeError):
            return []

    @app.template_filter('format_iocs')
    def format_iocs_filter(ioc_json):
        """Format IOC JSON for template display."""
        return format_iocs_display(ioc_json)

    # Register graph API blueprint
    from graph_routes import graph_bp
    app.register_blueprint(graph_bp)

    register_routes(app)
    return app


def register_routes(app):

    @app.route('/')
    def dashboard():
        session = get_session()
        try:
            total = session.query(func.count(Incident.id)).scalar() or 0

            now = datetime.now(timezone.utc)
            month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
            this_month = session.query(func.count(Incident.id)).filter(
                Incident.date >= month_start
            ).scalar() or 0

            critical = session.query(func.count(Incident.id)).filter(
                Incident.severity == 'Критичний'
            ).scalar() or 0

            # Last fetch
            last_fetch = session.query(FetchLog).order_by(desc(FetchLog.fetched_at)).first()
            last_fetch_time = last_fetch.fetched_at.strftime('%d.%m.%Y %H:%M') if last_fetch else 'Ще не оновлено'

            # Monthly data (last 12 months)
            twelve_months_ago = now - timedelta(days=365)
            monthly_raw = (
                session.query(
                    func.strftime('%Y-%m', Incident.date).label('month'),
                    func.count(Incident.id).label('count')
                )
                .filter(Incident.date >= twelve_months_ago)
                .group_by('month')
                .order_by('month')
                .all()
            )
            monthly_labels = [r[0] for r in monthly_raw]
            monthly_counts = [r[1] for r in monthly_raw]

            # By attack type
            type_raw = (
                session.query(Incident.attack_type, func.count(Incident.id))
                .filter(Incident.attack_type.isnot(None))
                .group_by(Incident.attack_type)
                .order_by(func.count(Incident.id).desc())
                .limit(8)
                .all()
            )
            type_labels = [r[0] for r in type_raw]
            type_counts = [r[1] for r in type_raw]

            # By sector
            sector_raw = (
                session.query(Incident.target_sector, func.count(Incident.id))
                .filter(Incident.target_sector.isnot(None))
                .group_by(Incident.target_sector)
                .order_by(func.count(Incident.id).desc())
                .all()
            )
            sector_labels = [r[0] for r in sector_raw]
            sector_counts = [r[1] for r in sector_raw]

            # By severity
            severity_raw = (
                session.query(Incident.severity, func.count(Incident.id))
                .filter(Incident.severity.isnot(None))
                .group_by(Incident.severity)
                .all()
            )
            severity_labels = [r[0] for r in severity_raw]
            severity_counts = [r[1] for r in severity_raw]

            # Recent incidents
            recent = session.query(Incident).order_by(desc(Incident.date)).limit(10).all()

            return render_template('dashboard.html',
                total=total,
                this_month=this_month,
                critical=critical,
                last_fetch_time=last_fetch_time,
                monthly_labels=monthly_labels,
                monthly_counts=monthly_counts,
                type_labels=type_labels,
                type_counts=type_counts,
                sector_labels=sector_labels,
                sector_counts=sector_counts,
                severity_labels=severity_labels,
                severity_counts=severity_counts,
                recent=recent,
            )
        finally:
            session.close()

    @app.route('/incidents')
    def incidents_list():
        session = get_session()
        try:
            page = request.args.get('page', 1, type=int)
            q = request.args.get('q', '').strip()
            attack_type = request.args.get('attack_type', '').strip()
            severity = request.args.get('severity', '').strip()
            source = request.args.get('source', '').strip()
            sector = request.args.get('sector', '').strip()
            date_from = request.args.get('date_from', '').strip()
            date_to = request.args.get('date_to', '').strip()

            query = session.query(Incident)

            if q:
                query = query.filter(
                    (Incident.title.ilike(f'%{q}%')) |
                    (Incident.description.ilike(f'%{q}%'))
                )
            if attack_type:
                query = query.filter(Incident.attack_type == attack_type)
            if severity:
                query = query.filter(Incident.severity == severity)
            if source:
                query = query.filter(Incident.source == source)
            if sector:
                query = query.filter(Incident.target_sector == sector)
            if date_from:
                try:
                    df = datetime.strptime(date_from, '%Y-%m-%d')
                    query = query.filter(Incident.date >= df)
                except ValueError:
                    pass
            if date_to:
                try:
                    dt = datetime.strptime(date_to, '%Y-%m-%d')
                    dt = dt.replace(hour=23, minute=59, second=59)
                    query = query.filter(Incident.date <= dt)
                except ValueError:
                    pass

            total = query.count()
            total_pages = max(1, (total + INCIDENTS_PER_PAGE - 1) // INCIDENTS_PER_PAGE)
            page = min(page, total_pages)

            incidents = (
                query.order_by(desc(Incident.date))
                .offset((page - 1) * INCIDENTS_PER_PAGE)
                .limit(INCIDENTS_PER_PAGE)
                .all()
            )

            # Filter options
            attack_types = list(ATTACK_TYPE_KEYWORDS.keys())
            sectors = list(SECTOR_KEYWORDS.keys())
            sources = [f['name'] for f in RSS_FEEDS] + ['Twitter/X', 'LinkedIn', 'Ручне введення']

            return render_template('incidents.html',
                incidents=incidents,
                page=page,
                total_pages=total_pages,
                total=total,
                q=q,
                attack_type=attack_type,
                severity=severity,
                source=source,
                sector=sector,
                date_from=date_from,
                date_to=date_to,
                attack_types=attack_types,
                severity_levels=SEVERITY_LEVELS,
                sectors=sectors,
                sources=sources,
            )
        finally:
            session.close()

    @app.route('/incidents/<int:incident_id>')
    def incident_detail(incident_id):
        session = get_session()
        try:
            incident = session.query(Incident).get(incident_id)
            if not incident:
                flash('Інцидент не знайдено', 'danger')
                return redirect(url_for('incidents_list'))

            technique_name = get_technique_name(incident.mitre_technique_id)

            return render_template('incident_detail.html',
                incident=incident,
                technique_name=technique_name,
            )
        finally:
            session.close()

    @app.route('/incidents/new', methods=['GET', 'POST'])
    def incident_new():
        if request.method == 'POST':
            session = get_session()
            try:
                title = request.form.get('title', '').strip()
                if not title:
                    flash('Назва інциденту обов\'язкова', 'danger')
                    return redirect(url_for('incident_new'))

                date_str = request.form.get('date', '').strip()
                date = None
                if date_str:
                    try:
                        date = datetime.strptime(date_str, '%Y-%m-%d').replace(tzinfo=timezone.utc)
                    except ValueError:
                        pass

                incident = Incident(
                    title=title,
                    description=request.form.get('description', '').strip() or None,
                    date=date or datetime.now(timezone.utc),
                    source=request.form.get('source', '').strip() or 'Ручне введення',
                    source_url=request.form.get('source_url', '').strip() or None,
                    attack_type=request.form.get('attack_type', '').strip() or None,
                    target_sector=request.form.get('target_sector', '').strip() or None,
                    threat_actor=request.form.get('threat_actor', '').strip() or None,
                    ioc_indicators=request.form.get('ioc_indicators', '').strip() or None,
                    severity=request.form.get('severity', '').strip() or 'Середній',
                    mitre_technique_id=request.form.get('mitre_technique_id', '').strip() or None,
                )
                session.add(incident)
                session.commit()
                flash('Інцидент успішно додано', 'success')
                return redirect(url_for('incident_detail', incident_id=incident.id))
            except IntegrityError:
                session.rollback()
                flash('Інцидент з таким URL вже існує', 'warning')
                return redirect(url_for('incident_new'))
            except Exception as e:
                session.rollback()
                flash(f'Помилка: {e}', 'danger')
                return redirect(url_for('incident_new'))
            finally:
                session.close()

        attack_types = list(ATTACK_TYPE_KEYWORDS.keys())
        sectors = list(SECTOR_KEYWORDS.keys())
        return render_template('incident_form.html',
            attack_types=attack_types,
            severity_levels=SEVERITY_LEVELS,
            sectors=sectors,
        )

    @app.route('/api/incidents')
    def api_incidents():
        session = get_session()
        try:
            q = request.args.get('q', '').strip()
            attack_type = request.args.get('attack_type', '').strip()
            severity = request.args.get('severity', '').strip()
            source = request.args.get('source', '').strip()
            limit = request.args.get('limit', 50, type=int)
            offset = request.args.get('offset', 0, type=int)

            query = session.query(Incident)

            if q:
                query = query.filter(
                    (Incident.title.ilike(f'%{q}%')) |
                    (Incident.description.ilike(f'%{q}%'))
                )
            if attack_type:
                query = query.filter(Incident.attack_type == attack_type)
            if severity:
                query = query.filter(Incident.severity == severity)
            if source:
                query = query.filter(Incident.source == source)

            total = query.count()
            incidents = (
                query.order_by(desc(Incident.date))
                .offset(offset)
                .limit(min(limit, 100))
                .all()
            )

            return jsonify({
                'total': total,
                'incidents': [i.to_dict() for i in incidents],
            })
        finally:
            session.close()

    @app.route('/fetch')
    def trigger_fetch():
        try:
            result = fetch_all_feeds()
            flash(
                f"Завантажено {result['total_added']} нових інцидентів з {result['total_found']} знайдених.",
                'success'
            )
        except Exception as e:
            flash(f'Помилка при завантаженні: {e}', 'danger')
        return redirect(url_for('dashboard'))

    @app.route('/translate')
    def trigger_translate():
        try:
            from translator import translate_untranslated
            result = translate_untranslated()
            flash(
                f"Перекладено {result['translated']} з {result['total']} інцидентів.",
                'success'
            )
        except Exception as e:
            flash(f'Помилка перекладу: {e}', 'danger')
        return redirect(url_for('dashboard'))

    @app.route('/scrape')
    def trigger_scrape():
        try:
            from scraper import scrape_unscraped
            result = scrape_unscraped()
            flash(
                f"Скраплено {result['scraped']} з {result['total']} статей.",
                'success'
            )
        except Exception as e:
            flash(f'Помилка скрапінгу: {e}', 'danger')
        return redirect(url_for('dashboard'))

    @app.route('/report')
    def trigger_report():
        try:
            from report_generator import generate_daily_report
            date_str = request.args.get('date', '').strip()
            target_date = None
            if date_str:
                try:
                    target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                except ValueError:
                    pass
            filepath = generate_daily_report(target_date)
            filename = os.path.basename(filepath)
            flash(
                f"Звіт створено: {filename} (на Робочому столі)",
                'success'
            )
        except Exception as e:
            flash(f'Помилка генерації звіту: {e}', 'danger')
        return redirect(url_for('dashboard'))

    @app.route('/report-org/<int:org_id>')
    def trigger_org_report(org_id):
        try:
            from report_generator import generate_org_report
            filepath = generate_org_report(org_id)
            filename = os.path.basename(filepath)
            flash(
                f"Звіт за організацією створено: {filename} (на Робочому столі)",
                'success'
            )
        except ValueError as e:
            flash(f'Організацію не знайдено: {e}', 'danger')
        except Exception as e:
            flash(f'Помилка генерації звіту: {e}', 'danger')
        return redirect(url_for('organization_detail', org_id=org_id))

    @app.route('/graph')
    def graph_page():
        return render_template('graph.html')

    @app.route('/fetch-twitter')
    def trigger_fetch_twitter():
        if not TWITTER_ENABLED:
            flash('Twitter API не налаштовано. Встановіть TWITTER_BEARER_TOKEN в .env', 'warning')
            return redirect(url_for('dashboard'))
        try:
            from twitter_fetcher import fetch_all_twitter
            result = fetch_all_twitter()
            flash(
                f"Twitter: {result.get('total_added', 0)} нових з {result.get('total_found', 0)} знайдених.",
                'success'
            )
        except Exception as e:
            flash(f'Помилка Twitter: {e}', 'danger')
        return redirect(url_for('dashboard'))

    @app.route('/fetch-linkedin')
    def trigger_fetch_linkedin():
        if not LINKEDIN_ENABLED:
            flash('LinkedIn моніторинг не налаштовано. Встановіть GOOGLE_CSE_API_KEY та GOOGLE_CSE_ID в .env', 'warning')
            return redirect(url_for('dashboard'))
        try:
            from linkedin_fetcher import fetch_all_linkedin
            result = fetch_all_linkedin()
            flash(
                f"LinkedIn: {result.get('total_added', 0)} нових з {result.get('total_found', 0)} знайдених.",
                'success'
            )
        except Exception as e:
            flash(f'Помилка LinkedIn: {e}', 'danger')
        return redirect(url_for('dashboard'))

    @app.route('/enrich')
    def trigger_enrich():
        if not VIRUSTOTAL_ENABLED and not ABUSEIPDB_ENABLED:
            flash('API збагачення не налаштовано. Встановіть ключі в .env', 'warning')
            return redirect(url_for('dashboard'))
        try:
            from ioc_enrichment import enrich_all_unenriched
            result = enrich_all_unenriched()
            flash(
                f"Збагачено {result.get('enriched', 0)} з {result.get('total', 0)} інцидентів.",
                'success'
            )
        except Exception as e:
            flash(f'Помилка збагачення IOC: {e}', 'danger')
        return redirect(url_for('dashboard'))

    # ==================== Threat Intelligence: Persons ====================

    @app.route('/persons')
    def persons_list():
        session = get_session()
        try:
            q = request.args.get('q', '').strip()
            role = request.args.get('role', '').strip()
            org = request.args.get('org', '').strip()

            query = session.query(ThreatPerson)
            if q:
                query = query.filter(
                    (ThreatPerson.name.ilike(f'%{q}%')) |
                    (ThreatPerson.aliases.ilike(f'%{q}%'))
                )
            if role:
                query = query.filter(ThreatPerson.role.ilike(f'%{role}%'))
            if org:
                query = query.filter(ThreatPerson.organization.ilike(f'%{org}%'))

            persons = query.order_by(ThreatPerson.name).all()

            # Get unique roles and orgs for filters
            all_roles = sorted(set(
                p.role for p in session.query(ThreatPerson).all() if p.role
            ))
            all_orgs = sorted(set(
                p.organization for p in session.query(ThreatPerson).all() if p.organization
            ))

            return render_template('persons.html',
                persons=persons,
                total=len(persons),
                q=q,
                role=role,
                org=org,
                all_roles=all_roles,
                all_orgs=all_orgs,
            )
        finally:
            session.close()

    @app.route('/persons/<int:person_id>')
    def person_detail(person_id):
        session = get_session()
        try:
            person = session.query(ThreatPerson).get(person_id)
            if not person:
                flash('Особу не знайдено', 'danger')
                return redirect(url_for('persons_list'))

            # Parse operations JSON
            operations = []
            if person.operations:
                try:
                    operations = json.loads(person.operations)
                except (json.JSONDecodeError, TypeError):
                    pass

            # Find related persons in same org
            related = []
            if person.organization:
                for org_name in person.organization.split(','):
                    org_name = org_name.strip()
                    if org_name:
                        rel = session.query(ThreatPerson).filter(
                            ThreatPerson.organization.ilike(f'%{org_name}%'),
                            ThreatPerson.id != person.id,
                        ).all()
                        related.extend(rel)
                # Deduplicate
                seen = set()
                unique_related = []
                for r in related:
                    if r.id not in seen:
                        seen.add(r.id)
                        unique_related.append(r)
                related = unique_related

            return render_template('person_detail.html',
                person=person,
                operations=operations,
                related=related,
            )
        finally:
            session.close()

    @app.route('/api/persons/search')
    def api_persons_search():
        session = get_session()
        try:
            q = request.args.get('q', '').strip()
            if not q:
                return jsonify({'results': []})

            persons = session.query(ThreatPerson).filter(
                (ThreatPerson.name.ilike(f'%{q}%')) |
                (ThreatPerson.aliases.ilike(f'%{q}%'))
            ).limit(10).all()

            return jsonify({
                'results': [p.to_dict() for p in persons],
            })
        finally:
            session.close()

    # ==================== Threat Intelligence: Organizations ====================

    @app.route('/organizations')
    def organizations_list():
        session = get_session()
        try:
            q = request.args.get('q', '').strip()
            org_type = request.args.get('org_type', '').strip()

            query = session.query(ThreatOrganization)
            if q:
                query = query.filter(
                    (ThreatOrganization.name.ilike(f'%{q}%')) |
                    (ThreatOrganization.aliases.ilike(f'%{q}%'))
                )
            if org_type:
                query = query.filter(ThreatOrganization.org_type == org_type)

            orgs = query.order_by(ThreatOrganization.name).all()

            all_types = sorted(set(
                o.org_type for o in session.query(ThreatOrganization).all() if o.org_type
            ))

            return render_template('organizations.html',
                orgs=orgs,
                total=len(orgs),
                q=q,
                org_type=org_type,
                all_types=all_types,
            )
        finally:
            session.close()

    @app.route('/organizations/<int:org_id>')
    def organization_detail(org_id):
        session = get_session()
        try:
            org = session.query(ThreatOrganization).get(org_id)
            if not org:
                flash('Організацію не знайдено', 'danger')
                return redirect(url_for('organizations_list'))

            operations = []
            if org.known_operations:
                try:
                    operations = json.loads(org.known_operations)
                except (json.JSONDecodeError, TypeError):
                    pass

            # Find members (persons linked to this org)
            members = session.query(ThreatPerson).filter(
                ThreatPerson.organization.ilike(f'%{org.name}%')
            ).all()

            return render_template('organization_detail.html',
                org=org,
                operations=operations,
                members=members,
            )
        finally:
            session.close()

    # ==================== Import Threat Intel ====================

    @app.route('/import-threat-intel')
    def trigger_import_threat_intel():
        try:
            from threat_intel_parser import import_threat_intel
            result = import_threat_intel()
            flash(
                f"Імпортовано: {result['persons_added']} осіб, {result['orgs_added']} організацій "
                f"(всього: {result['total_persons']} осіб, {result['total_orgs']} організацій).",
                'success'
            )
        except Exception as e:
            flash(f'Помилка імпорту: {e}', 'danger')
        return redirect(url_for('persons_list'))

    @app.route('/images/<path:path>')
    def article_image(path):
        """Serve article images from data/images/."""
        images_dir = os.path.join(BASE_DIR, 'data', 'images')
        # Validate that path stays within images_dir
        safe_path = os.path.normpath(os.path.join(images_dir, path))
        if not safe_path.startswith(os.path.normpath(images_dir)):
            abort(404)
        if not os.path.isfile(safe_path):
            abort(404)
        return send_from_directory(os.path.dirname(safe_path), os.path.basename(safe_path))

    # ==================== IOC Threat Intelligence Feeds ====================

    @app.route('/ioc')
    def ioc_list():
        session = get_session()
        try:
            page = request.args.get('page', 1, type=int)
            q = request.args.get('q', '').strip()
            ioc_type = request.args.get('ioc_type', '').strip()
            source = request.args.get('source', '').strip()
            threat_level = request.args.get('threat_level', '').strip()

            query = session.query(IOCIndicator)

            if q:
                query = query.filter(
                    (IOCIndicator.value.ilike(f'%{q}%')) |
                    (IOCIndicator.tags.ilike(f'%{q}%')) |
                    (IOCIndicator.description.ilike(f'%{q}%'))
                )
            if ioc_type:
                query = query.filter(IOCIndicator.ioc_type == ioc_type)
            if source:
                query = query.filter(IOCIndicator.source == source)
            if threat_level:
                query = query.filter(IOCIndicator.threat_level == threat_level)

            total = query.count()
            total_pages = max(1, (total + IOC_PER_PAGE - 1) // IOC_PER_PAGE)
            page = min(page, total_pages)

            iocs = (
                query.order_by(desc(IOCIndicator.last_seen))
                .offset((page - 1) * IOC_PER_PAGE)
                .limit(IOC_PER_PAGE)
                .all()
            )

            # Stats
            total_all = session.query(func.count(IOCIndicator.id)).scalar() or 0
            critical_count = session.query(func.count(IOCIndicator.id)).filter(
                IOCIndicator.threat_level == 'critical'
            ).scalar() or 0
            sources_count = session.query(func.count(func.distinct(IOCIndicator.source))).scalar() or 0
            last_ioc = session.query(IOCIndicator).order_by(desc(IOCIndicator.created_at)).first()
            last_update = last_ioc.created_at.strftime('%d.%m.%Y %H:%M') if last_ioc and last_ioc.created_at else 'Ще не оновлено'

            # Filter options
            all_sources = sorted(set(
                r[0] for r in session.query(IOCIndicator.source).distinct().all() if r[0]
            ))
            all_types = sorted(set(
                r[0] for r in session.query(IOCIndicator.ioc_type).distinct().all() if r[0]
            ))

            return render_template('ioc_list.html',
                iocs=iocs,
                page=page,
                total_pages=total_pages,
                total=total,
                total_all=total_all,
                critical_count=critical_count,
                sources_count=sources_count,
                last_update=last_update,
                q=q,
                ioc_type=ioc_type,
                source=source,
                threat_level=threat_level,
                all_sources=all_sources,
                all_types=all_types,
                threat_levels=IOC_THREAT_LEVELS,
                threat_level_labels=IOC_THREAT_LEVEL_LABELS,
                type_labels=IOC_TYPE_LABELS,
            )
        finally:
            session.close()

    @app.route('/ioc/<int:ioc_id>')
    def ioc_detail(ioc_id):
        session = get_session()
        try:
            ioc = session.query(IOCIndicator).get(ioc_id)
            if not ioc:
                flash('IOC індикатор не знайдено', 'danger')
                return redirect(url_for('ioc_list'))

            # Parse enrichment data
            enrichment = None
            if ioc.enrichment_data:
                try:
                    enrichment = json.loads(ioc.enrichment_data)
                except (json.JSONDecodeError, TypeError):
                    pass

            return render_template('ioc_detail.html',
                ioc=ioc,
                enrichment=enrichment,
                threat_level_labels=IOC_THREAT_LEVEL_LABELS,
                type_labels=IOC_TYPE_LABELS,
            )
        finally:
            session.close()

    @app.route('/fetch-ioc-feeds')
    def trigger_fetch_ioc_feeds():
        if not IOC_FEEDS_ENABLED:
            flash('IOC фіди вимкнено в конфігурації', 'warning')
            return redirect(url_for('ioc_list'))
        try:
            from ioc_feed_fetcher import fetch_all_ioc_feeds
            result = fetch_all_ioc_feeds()
            flash(
                f"IOC фіди: {result['total_added']} нових з {result['total_found']} знайдених.",
                'success'
            )
        except Exception as e:
            flash(f'Помилка завантаження IOC фідів: {e}', 'danger')
        return redirect(url_for('ioc_list'))

    @app.route('/report-ioc')
    def trigger_ioc_report():
        try:
            from report_generator import generate_ioc_report
            ioc_type = request.args.get('ioc_type', '').strip() or None
            threat_level = request.args.get('threat_level', '').strip() or None
            source = request.args.get('source', '').strip() or None
            filepath = generate_ioc_report(ioc_type, threat_level, source)
            filename = os.path.basename(filepath)
            flash(
                f"IOC звіт створено: {filename} (на Робочому столі)",
                'success'
            )
        except Exception as e:
            flash(f'Помилка генерації IOC звіту: {e}', 'danger')
        return redirect(url_for('ioc_list'))

    @app.route('/api/ioc')
    def api_ioc():
        session = get_session()
        try:
            q = request.args.get('q', '').strip()
            ioc_type = request.args.get('ioc_type', '').strip()
            source = request.args.get('source', '').strip()
            threat_level = request.args.get('threat_level', '').strip()
            limit = request.args.get('limit', 50, type=int)
            offset = request.args.get('offset', 0, type=int)

            query = session.query(IOCIndicator)

            if q:
                query = query.filter(
                    (IOCIndicator.value.ilike(f'%{q}%')) |
                    (IOCIndicator.tags.ilike(f'%{q}%'))
                )
            if ioc_type:
                query = query.filter(IOCIndicator.ioc_type == ioc_type)
            if source:
                query = query.filter(IOCIndicator.source == source)
            if threat_level:
                query = query.filter(IOCIndicator.threat_level == threat_level)

            total = query.count()
            iocs = (
                query.order_by(desc(IOCIndicator.last_seen))
                .offset(offset)
                .limit(min(limit, 200))
                .all()
            )

            return jsonify({
                'total': total,
                'iocs': [i.to_dict() for i in iocs],
            })
        finally:
            session.close()

    # ==================== Document Analysis (PDF) ====================

    @app.route('/documents')
    def documents_list():
        session = get_session()
        try:
            page = request.args.get('page', 1, type=int)
            q = request.args.get('q', '').strip()
            doc_type = request.args.get('doc_type', '').strip()

            query = session.query(UploadedDocument)

            if q:
                query = query.filter(
                    (UploadedDocument.original_name.ilike(f'%{q}%')) |
                    (UploadedDocument.title.ilike(f'%{q}%')) |
                    (UploadedDocument.threat_actors.ilike(f'%{q}%')) |
                    (UploadedDocument.summary.ilike(f'%{q}%'))
                )
            if doc_type:
                query = query.filter(UploadedDocument.doc_type == doc_type)

            total = query.count()
            total_pages = max(1, (total + DOCS_PER_PAGE - 1) // DOCS_PER_PAGE)
            page = min(page, total_pages)

            docs = (
                query.order_by(desc(UploadedDocument.created_at))
                .offset((page - 1) * DOCS_PER_PAGE)
                .limit(DOCS_PER_PAGE)
                .all()
            )

            # Stats
            total_all = session.query(func.count(UploadedDocument.id)).scalar() or 0
            total_iocs = session.query(func.coalesce(func.sum(UploadedDocument.ioc_count), 0)).scalar() or 0
            total_pages_all = session.query(func.coalesce(func.sum(UploadedDocument.page_count), 0)).scalar() or 0

            return render_template('documents.html',
                docs=docs,
                page=page,
                total_pages=total_pages,
                total=total,
                total_all=total_all,
                total_iocs=total_iocs,
                total_pages_all=total_pages_all,
                q=q,
                doc_type=doc_type,
                allowed_extensions=ALLOWED_EXTENSIONS,
                max_size_mb=MAX_UPLOAD_SIZE_MB,
            )
        finally:
            session.close()

    @app.route('/documents/upload', methods=['POST'])
    def document_upload():
        if 'file' not in request.files:
            flash('Файл не обрано', 'danger')
            return redirect(url_for('documents_list'))

        file = request.files['file']
        if not file.filename:
            flash('Файл не обрано', 'danger')
            return redirect(url_for('documents_list'))

        # Check extension
        ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
        if ext not in ALLOWED_EXTENSIONS:
            flash(f'Непідтримуваний формат. Дозволені: {", ".join(ALLOWED_EXTENSIONS)}', 'warning')
            return redirect(url_for('documents_list'))

        try:
            from pdf_analyzer import save_uploaded_file, analyze_document
            filepath, original_name, doc_type = save_uploaded_file(file)
            doc = analyze_document(filepath, original_name, doc_type)
            flash(
                f'Документ "{original_name}" проаналізовано: {doc.ioc_count} IOC, '
                f'{doc.page_count} сторінок',
                'success'
            )
            return redirect(url_for('document_detail', doc_id=doc.id))
        except Exception as e:
            flash(f'Помилка аналізу документа: {e}', 'danger')
            return redirect(url_for('documents_list'))

    @app.route('/documents/<int:doc_id>')
    def document_detail(doc_id):
        session = get_session()
        try:
            doc = session.query(UploadedDocument).get(doc_id)
            if not doc:
                flash('Документ не знайдено', 'danger')
                return redirect(url_for('documents_list'))

            # Parse JSON fields
            ioc_data = {}
            if doc.ioc_data:
                try:
                    ioc_data = json.loads(doc.ioc_data)
                except (json.JSONDecodeError, TypeError):
                    pass

            keywords = {}
            if doc.keywords:
                try:
                    keywords = json.loads(doc.keywords)
                except (json.JSONDecodeError, TypeError):
                    pass

            return render_template('document_detail.html',
                doc=doc,
                ioc_data=ioc_data,
                keywords=keywords,
                type_labels=IOC_TYPE_LABELS,
            )
        finally:
            session.close()

    @app.route('/documents/<int:doc_id>/sync-graph')
    def document_sync_graph(doc_id):
        """Sync a document and its IOCs to Neo4j graph."""
        try:
            from graph_sync import sync_document_to_graph
            result = sync_document_to_graph(doc_id)
            if result:
                flash('Документ синхронізовано з графовою базою Neo4j', 'success')
            else:
                flash('Не вдалося синхронізувати з Neo4j. Перевірте підключення.', 'warning')
        except Exception as e:
            flash(f'Помилка синхронізації: {e}', 'danger')
        return redirect(url_for('document_detail', doc_id=doc_id))

    @app.route('/sync-all-graph')
    def trigger_sync_all_graph():
        """Sync ALL data types to Neo4j: incidents, persons, orgs, documents, IOC feeds."""
        try:
            from graph_sync import sync_all_to_graph
            result = sync_all_to_graph()
            msg_parts = []
            if result.get('incidents_synced', 0):
                msg_parts.append(f"{result['incidents_synced']} інцидентів")
            if result.get('persons_synced', 0):
                msg_parts.append(f"{result['persons_synced']} осіб")
            if result.get('orgs_synced', 0):
                msg_parts.append(f"{result['orgs_synced']} організацій")
            if result.get('documents_synced', 0):
                msg_parts.append(f"{result['documents_synced']} документів")
            if result.get('ioc_feeds_synced', 0):
                msg_parts.append(f"{result['ioc_feeds_synced']} IOC з фідів")

            if msg_parts:
                flash(f"Синхронізовано з Neo4j: {', '.join(msg_parts)}", 'success')
            else:
                flash("Немає нових даних для синхронізації або Neo4j недоступний", 'info')
        except Exception as e:
            flash(f'Помилка синхронізації: {e}', 'danger')
        return redirect(url_for('graph_page'))

    @app.route('/api/documents')
    def api_documents():
        session = get_session()
        try:
            q = request.args.get('q', '').strip()
            limit = request.args.get('limit', 50, type=int)
            offset = request.args.get('offset', 0, type=int)

            query = session.query(UploadedDocument)
            if q:
                query = query.filter(
                    (UploadedDocument.original_name.ilike(f'%{q}%')) |
                    (UploadedDocument.title.ilike(f'%{q}%'))
                )

            total = query.count()
            docs = (
                query.order_by(desc(UploadedDocument.created_at))
                .offset(offset)
                .limit(min(limit, 100))
                .all()
            )

            return jsonify({
                'total': total,
                'documents': [d.to_dict() for d in docs],
            })
        finally:
            session.close()

    @app.errorhandler(404)
    def not_found(e):
        return render_template('base.html', error='Сторінку не знайдено (404)'), 404
