#!/usr/bin/env python3
"""
VerityFlux Enterprise - Background Worker
Handles async tasks like scanning, notifications, and maintenance

For air-gapped deployments, this worker processes tasks from a local queue.
For connected deployments, it can use Redis as the queue backend.
"""

import os
import sys
import time
import json
import signal
import logging
import asyncio
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, List, Callable
from dataclasses import dataclass, field
from enum import Enum
import threading
from queue import Queue, Empty
import traceback

# Configure logging
logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("verityflux.worker")


# =============================================================================
# TASK DEFINITIONS
# =============================================================================

class TaskStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TaskPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class Task:
    """Background task definition"""
    id: str
    task_type: str
    payload: Dict[str, Any]
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    retries: int = 0
    max_retries: int = 3
    
    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "task_type": self.task_type,
            "payload": self.payload,
            "priority": self.priority.value,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result,
            "error": self.error,
            "retries": self.retries,
        }


# =============================================================================
# TASK HANDLERS
# =============================================================================

class TaskHandlers:
    """Collection of task handler functions"""
    
    @staticmethod
    async def run_scan(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a security scan"""
        scan_id = payload.get("scan_id")
        target = payload.get("target", {})
        config = payload.get("config", {})
        
        logger.info(f"Running scan {scan_id} for target {target.get('name')}")
        
        # Simulate scan execution
        profile = config.get("profile", "standard")
        
        if profile == "quick":
            await asyncio.sleep(5)
            findings_count = 2
        elif profile == "deep":
            await asyncio.sleep(30)
            findings_count = 8
        else:  # standard
            await asyncio.sleep(15)
            findings_count = 5
        
        return {
            "scan_id": scan_id,
            "status": "completed",
            "findings_count": findings_count,
            "risk_score": 45.0 if findings_count > 0 else 0,
            "completed_at": datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    async def send_notification(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send a notification"""
        notification_id = payload.get("notification_id")
        channels = payload.get("channels", [])
        title = payload.get("title")
        message = payload.get("message")
        
        logger.info(f"Sending notification {notification_id} to {channels}")
        
        results = {}
        for channel in channels:
            # In air-gapped mode, write to local file
            # In connected mode, would send via actual integrations
            results[channel] = {"success": True, "message": "Queued locally"}
        
        # Write to notifications log
        notifications_dir = Path(os.getenv("DATA_DIR", "/app/data")) / "notifications"
        notifications_dir.mkdir(parents=True, exist_ok=True)
        
        notification_file = notifications_dir / f"{datetime.utcnow().strftime('%Y-%m-%d')}.jsonl"
        with open(notification_file, "a") as f:
            f.write(json.dumps({
                "id": notification_id,
                "timestamp": datetime.utcnow().isoformat(),
                "title": title,
                "message": message,
                "channels": channels,
                "results": results,
            }) + "\n")
        
        return {"notification_id": notification_id, "results": results}
    
    @staticmethod
    async def process_approval_timeout(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Handle approval request timeout"""
        approval_id = payload.get("approval_id")
        action = payload.get("timeout_action", "deny")
        
        logger.info(f"Processing approval timeout for {approval_id}, action: {action}")
        
        # In a real implementation, would update the approval in the database
        return {
            "approval_id": approval_id,
            "action_taken": action,
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    async def cleanup_expired_data(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Clean up expired data"""
        data_type = payload.get("data_type", "all")
        retention_days = payload.get("retention_days", 30)
        
        logger.info(f"Cleaning up {data_type} data older than {retention_days} days")
        
        cleaned = {
            "events": 0,
            "scans": 0,
            "notifications": 0,
        }
        
        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        data_dir = Path(os.getenv("DATA_DIR", "/app/data"))
        
        # Clean old scan results
        scans_dir = data_dir / "scans"
        if scans_dir.exists():
            for scan_file in scans_dir.glob("*.json"):
                try:
                    mtime = datetime.fromtimestamp(scan_file.stat().st_mtime)
                    if mtime < cutoff:
                        scan_file.unlink()
                        cleaned["scans"] += 1
                except Exception as e:
                    logger.warning(f"Failed to clean {scan_file}: {e}")
        
        return {"cleaned": cleaned, "cutoff_date": cutoff.isoformat()}
    
    @staticmethod
    async def generate_report(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a report"""
        report_type = payload.get("report_type", "security_summary")
        date_range = payload.get("date_range", "last_7_days")
        
        logger.info(f"Generating {report_type} report for {date_range}")
        
        # Simulate report generation
        await asyncio.sleep(5)
        
        report_id = f"report-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        
        return {
            "report_id": report_id,
            "report_type": report_type,
            "date_range": date_range,
            "generated_at": datetime.utcnow().isoformat(),
            "status": "completed",
        }
    
    @staticmethod
    async def sync_vulnerability_db(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Sync vulnerability database (for connected mode)"""
        source = payload.get("source", "all")
        
        logger.info(f"Syncing vulnerability database from {source}")
        
        # In air-gapped mode, this would check for local update packages
        # In connected mode, would fetch from external sources
        
        updates_dir = Path(os.getenv("OFFLINE_UPDATES_PATH", "/app/data/updates"))
        pending_updates = list(updates_dir.glob("*.tar.gz"))
        
        return {
            "source": source,
            "pending_updates": len(pending_updates),
            "sync_time": datetime.utcnow().isoformat(),
        }
    
    @staticmethod
    async def agent_health_check(payload: Dict[str, Any]) -> Dict[str, Any]:
        """Check health of registered agents"""
        logger.info("Running agent health checks")
        
        # Would check last heartbeat times and update agent status
        # For now, return simulated results
        
        return {
            "total_agents": 5,
            "healthy": 4,
            "unhealthy": 1,
            "check_time": datetime.utcnow().isoformat(),
        }


# =============================================================================
# TASK QUEUE
# =============================================================================

class LocalTaskQueue:
    """File-based task queue for air-gapped deployments"""
    
    def __init__(self, queue_dir: str = None):
        self.queue_dir = Path(queue_dir or os.getenv("DATA_DIR", "/app/data")) / "queue"
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        self.pending_dir = self.queue_dir / "pending"
        self.processing_dir = self.queue_dir / "processing"
        self.completed_dir = self.queue_dir / "completed"
        self.failed_dir = self.queue_dir / "failed"
        
        for d in [self.pending_dir, self.processing_dir, self.completed_dir, self.failed_dir]:
            d.mkdir(exist_ok=True)
    
    def enqueue(self, task: Task) -> str:
        """Add task to queue"""
        task_file = self.pending_dir / f"{task.priority.value:02d}_{task.id}.json"
        with open(task_file, "w") as f:
            json.dump(task.to_dict(), f)
        logger.debug(f"Enqueued task {task.id}")
        return task.id
    
    def dequeue(self) -> Optional[Task]:
        """Get next task from queue"""
        pending_files = sorted(self.pending_dir.glob("*.json"), reverse=True)
        
        for task_file in pending_files:
            try:
                # Move to processing
                processing_file = self.processing_dir / task_file.name
                task_file.rename(processing_file)
                
                with open(processing_file) as f:
                    data = json.load(f)
                
                task = Task(
                    id=data["id"],
                    task_type=data["task_type"],
                    payload=data["payload"],
                    priority=TaskPriority(data.get("priority", 2)),
                    status=TaskStatus.RUNNING,
                    created_at=datetime.fromisoformat(data["created_at"]),
                    retries=data.get("retries", 0),
                    max_retries=data.get("max_retries", 3),
                )
                task.started_at = datetime.utcnow()
                
                # Update file with started_at
                with open(processing_file, "w") as f:
                    json.dump(task.to_dict(), f)
                
                return task
            except Exception as e:
                logger.warning(f"Failed to dequeue task from {task_file}: {e}")
                continue
        
        return None
    
    def complete(self, task: Task, result: Dict[str, Any]):
        """Mark task as completed"""
        task.status = TaskStatus.COMPLETED
        task.completed_at = datetime.utcnow()
        task.result = result
        
        processing_file = self.processing_dir / f"{task.priority.value:02d}_{task.id}.json"
        completed_file = self.completed_dir / f"{task.id}.json"
        
        with open(completed_file, "w") as f:
            json.dump(task.to_dict(), f)
        
        if processing_file.exists():
            processing_file.unlink()
        
        logger.debug(f"Completed task {task.id}")
    
    def fail(self, task: Task, error: str):
        """Mark task as failed"""
        task.error = error
        
        processing_file = self.processing_dir / f"{task.priority.value:02d}_{task.id}.json"
        
        if task.retries < task.max_retries:
            # Requeue for retry
            task.status = TaskStatus.PENDING
            task.retries += 1
            
            pending_file = self.pending_dir / f"{task.priority.value:02d}_{task.id}.json"
            with open(pending_file, "w") as f:
                json.dump(task.to_dict(), f)
            
            logger.info(f"Requeued task {task.id} for retry ({task.retries}/{task.max_retries})")
        else:
            # Move to failed
            task.status = TaskStatus.FAILED
            task.completed_at = datetime.utcnow()
            
            failed_file = self.failed_dir / f"{task.id}.json"
            with open(failed_file, "w") as f:
                json.dump(task.to_dict(), f)
            
            logger.error(f"Task {task.id} failed permanently: {error}")
        
        if processing_file.exists():
            processing_file.unlink()
    
    def get_stats(self) -> Dict[str, int]:
        """Get queue statistics"""
        return {
            "pending": len(list(self.pending_dir.glob("*.json"))),
            "processing": len(list(self.processing_dir.glob("*.json"))),
            "completed": len(list(self.completed_dir.glob("*.json"))),
            "failed": len(list(self.failed_dir.glob("*.json"))),
        }


# =============================================================================
# WORKER
# =============================================================================

class Worker:
    """Background task worker"""
    
    def __init__(
        self,
        queue: LocalTaskQueue = None,
        concurrency: int = 4,
        poll_interval: float = 1.0,
    ):
        self.queue = queue or LocalTaskQueue()
        self.concurrency = concurrency
        self.poll_interval = poll_interval
        self.running = False
        self.handlers: Dict[str, Callable] = {}
        self._register_default_handlers()
    
    def _register_default_handlers(self):
        """Register default task handlers"""
        self.handlers = {
            "run_scan": TaskHandlers.run_scan,
            "send_notification": TaskHandlers.send_notification,
            "process_approval_timeout": TaskHandlers.process_approval_timeout,
            "cleanup_expired_data": TaskHandlers.cleanup_expired_data,
            "generate_report": TaskHandlers.generate_report,
            "sync_vulnerability_db": TaskHandlers.sync_vulnerability_db,
            "agent_health_check": TaskHandlers.agent_health_check,
        }
    
    def register_handler(self, task_type: str, handler: Callable):
        """Register a task handler"""
        self.handlers[task_type] = handler
    
    async def process_task(self, task: Task):
        """Process a single task"""
        handler = self.handlers.get(task.task_type)
        
        if not handler:
            self.queue.fail(task, f"No handler for task type: {task.task_type}")
            return
        
        try:
            logger.info(f"Processing task {task.id} ({task.task_type})")
            result = await handler(task.payload)
            self.queue.complete(task, result)
            logger.info(f"Task {task.id} completed successfully")
        except Exception as e:
            logger.error(f"Task {task.id} failed: {e}")
            logger.debug(traceback.format_exc())
            self.queue.fail(task, str(e))
    
    async def run(self):
        """Run the worker loop"""
        self.running = True
        logger.info(f"Worker started with concurrency={self.concurrency}")
        
        semaphore = asyncio.Semaphore(self.concurrency)
        tasks = set()
        
        while self.running:
            try:
                # Get next task
                task = self.queue.dequeue()
                
                if task:
                    async def process_with_semaphore(t):
                        async with semaphore:
                            await self.process_task(t)
                    
                    task_coro = asyncio.create_task(process_with_semaphore(task))
                    tasks.add(task_coro)
                    task_coro.add_done_callback(tasks.discard)
                else:
                    # No tasks available, wait before polling again
                    await asyncio.sleep(self.poll_interval)
                
                # Clean up completed tasks
                done_tasks = [t for t in tasks if t.done()]
                for t in done_tasks:
                    tasks.discard(t)
                    
            except Exception as e:
                logger.error(f"Worker error: {e}")
                await asyncio.sleep(self.poll_interval)
        
        # Wait for remaining tasks to complete
        if tasks:
            logger.info(f"Waiting for {len(tasks)} tasks to complete...")
            await asyncio.gather(*tasks, return_exceptions=True)
        
        logger.info("Worker stopped")
    
    def stop(self):
        """Stop the worker"""
        logger.info("Stopping worker...")
        self.running = False


# =============================================================================
# SCHEDULED TASKS
# =============================================================================

class Scheduler:
    """Simple task scheduler"""
    
    def __init__(self, queue: LocalTaskQueue):
        self.queue = queue
        self.schedules: List[Dict] = []
        self.running = False
    
    def add_schedule(
        self,
        task_type: str,
        payload: Dict[str, Any],
        interval_seconds: int,
        priority: TaskPriority = TaskPriority.NORMAL,
    ):
        """Add a scheduled task"""
        self.schedules.append({
            "task_type": task_type,
            "payload": payload,
            "interval": interval_seconds,
            "priority": priority,
            "last_run": None,
        })
    
    async def run(self):
        """Run the scheduler loop"""
        self.running = True
        logger.info(f"Scheduler started with {len(self.schedules)} schedules")
        
        while self.running:
            now = datetime.utcnow()
            
            for schedule in self.schedules:
                last_run = schedule.get("last_run")
                interval = schedule["interval"]
                
                if last_run is None or (now - last_run).total_seconds() >= interval:
                    # Time to run this task
                    import uuid
                    task = Task(
                        id=str(uuid.uuid4()),
                        task_type=schedule["task_type"],
                        payload=schedule["payload"],
                        priority=schedule["priority"],
                    )
                    self.queue.enqueue(task)
                    schedule["last_run"] = now
                    logger.debug(f"Scheduled task {schedule['task_type']}")
            
            await asyncio.sleep(60)  # Check every minute
        
        logger.info("Scheduler stopped")
    
    def stop(self):
        """Stop the scheduler"""
        self.running = False


# =============================================================================
# MAIN
# =============================================================================

async def main():
    """Main entry point"""
    logger.info("=" * 60)
    logger.info("VerityFlux Enterprise - Background Worker")
    logger.info("=" * 60)
    
    # Create queue
    queue = LocalTaskQueue()
    
    # Create worker
    concurrency = int(os.getenv("WORKER_CONCURRENCY", "4"))
    worker = Worker(queue=queue, concurrency=concurrency)
    
    # Create scheduler
    scheduler = Scheduler(queue)
    
    # Add scheduled tasks
    scheduler.add_schedule(
        task_type="cleanup_expired_data",
        payload={"data_type": "all", "retention_days": 30},
        interval_seconds=86400,  # Daily
        priority=TaskPriority.LOW,
    )
    
    scheduler.add_schedule(
        task_type="agent_health_check",
        payload={},
        interval_seconds=300,  # Every 5 minutes
        priority=TaskPriority.HIGH,
    )
    
    scheduler.add_schedule(
        task_type="sync_vulnerability_db",
        payload={"source": "local"},
        interval_seconds=3600,  # Hourly
        priority=TaskPriority.NORMAL,
    )
    
    # Handle shutdown
    def signal_handler(sig, frame):
        logger.info(f"Received signal {sig}")
        worker.stop()
        scheduler.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run worker and scheduler concurrently
    await asyncio.gather(
        worker.run(),
        scheduler.run(),
    )


if __name__ == "__main__":
    asyncio.run(main())
