import main as worker_main


youtube_api_item_to_entry = worker_main.youtube_api_item_to_entry
youtube_uploads_playlist_id = worker_main.youtube_uploads_playlist_id


if __name__ == "__main__":
    worker_main.loop()
