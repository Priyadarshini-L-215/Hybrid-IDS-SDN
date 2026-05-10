import asyncio
import pytest
from unittest.mock import patch, MagicMock

from common.db_writer import AsyncAlertWriter

@pytest.fixture
def mock_db():
    with patch('common.db_writer.db') as mock:
        yield mock

@pytest.mark.asyncio
async def test_writer_start_stop():
    writer = AsyncAlertWriter()
    await writer.start()
    assert writer._running is True
    assert writer._worker_task is not None
    assert not writer._worker_task.done()

    await writer.stop()
    assert writer._running is False
    assert writer._worker_task.done()

@pytest.mark.asyncio
async def test_writer_add_alert(mock_db):
    writer = AsyncAlertWriter(batch_size=2, flush_interval=0.1)
    await writer.start()

    await writer.add_alert({"test": 1})
    await writer.add_alert({"test": 2})

    # Wait a bit for the flush worker to process
    await asyncio.sleep(0.2)

    mock_db.batch_add_alerts.assert_called_once()
    args, _ = mock_db.batch_add_alerts.call_args
    assert args[0] == [{"test": 1}, {"test": 2}]

    await writer.stop()

@pytest.mark.asyncio
async def test_writer_add_alerts(mock_db):
    writer = AsyncAlertWriter(batch_size=3, flush_interval=0.1)
    await writer.start()

    await writer.add_alerts([{"test": 1}, {"test": 2}, {"test": 3}])

    # Wait a bit for the flush worker to process
    await asyncio.sleep(0.2)

    mock_db.batch_add_alerts.assert_called_once()
    args, _ = mock_db.batch_add_alerts.call_args
    assert args[0] == [{"test": 1}, {"test": 2}, {"test": 3}]

    await writer.stop()

@pytest.mark.asyncio
async def test_writer_flush_interval(mock_db):
    writer = AsyncAlertWriter(batch_size=5, flush_interval=0.1)
    await writer.start()

    # Add only 1 alert, should flush after flush_interval
    await writer.add_alert({"test": 1})

    await asyncio.sleep(0.2)

    mock_db.batch_add_alerts.assert_called_once_with([{"test": 1}])

    await writer.stop()


@pytest.mark.asyncio
async def test_writer_error_handling_no_hang(mock_db):
    """
    Test that if batch_add_alerts raises an Exception,
    the writer can still be stopped cleanly (does not hang).
    """
    mock_db.batch_add_alerts.side_effect = Exception("DB mock error")

    writer = AsyncAlertWriter(batch_size=2, flush_interval=0.1)
    await writer.start()

    await writer.add_alert({"test": 1})
    await writer.add_alert({"test": 2})

    # Let the flush worker pick them up and fail
    await asyncio.sleep(0.2)

    # If the bug exists, writer.stop() will hang forever waiting on queue.join().
    # We use wait_for so the test doesn't lock up entirely.
    try:
        await asyncio.wait_for(writer.stop(), timeout=1.0)
    except asyncio.TimeoutError:
        pytest.fail("writer.stop() hung because task_done() was not called on error")
