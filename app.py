import os
import json

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_from_directory, abort
from sqlalchemy import func, desc
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta, timezone

from database import init_db, get_session, Session
from models import Incident, FetchLog
from rss_parser import fetch_all_feeds
from mitre_data import get_technique_name
from config import (
    SECRET_KEY, SEVERITY_LEVELS, ATTACK_TYPE_KEYWORDS,
    SECTOR_KEYWORDS, INCIDENTS_PER_PAGE, RSS_FEEDS, BASE_DIR,
    TWITTER_ENABLED, VIRUSTOTAL_ENABLED, ABUSEIPDB_ENABLED,
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
            sources = [f['name'] for f in RSS_FEEDS] + ['Twitter/X', 'Ручне введення']

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

    @app.errorhandler(404)
    def not_found(e):
        return render_template('base.html', error='Сторінку не знайдено (404)'), 404
