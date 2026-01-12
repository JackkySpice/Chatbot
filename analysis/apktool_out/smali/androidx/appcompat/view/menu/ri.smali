.class public Landroidx/appcompat/view/menu/ri;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/h8;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/ri$d;,
        Landroidx/appcompat/view/menu/ri$c;,
        Landroidx/appcompat/view/menu/ri$b;
    }
.end annotation


# instance fields
.field public final a:Lio/flutter/embedding/engine/FlutterJNI;

.field public final b:Landroid/content/res/AssetManager;

.field public final c:Landroidx/appcompat/view/menu/ti;

.field public final d:Landroidx/appcompat/view/menu/h8;

.field public e:Z

.field public f:Ljava/lang/String;

.field public final g:Landroidx/appcompat/view/menu/h8$a;


# direct methods
.method public constructor <init>(Lio/flutter/embedding/engine/FlutterJNI;Landroid/content/res/AssetManager;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/ri;->e:Z

    new-instance v0, Landroidx/appcompat/view/menu/ri$a;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/ri$a;-><init>(Landroidx/appcompat/view/menu/ri;)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/ri;->g:Landroidx/appcompat/view/menu/h8$a;

    iput-object p1, p0, Landroidx/appcompat/view/menu/ri;->a:Lio/flutter/embedding/engine/FlutterJNI;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ri;->b:Landroid/content/res/AssetManager;

    new-instance p2, Landroidx/appcompat/view/menu/ti;

    invoke-direct {p2, p1}, Landroidx/appcompat/view/menu/ti;-><init>(Lio/flutter/embedding/engine/FlutterJNI;)V

    iput-object p2, p0, Landroidx/appcompat/view/menu/ri;->c:Landroidx/appcompat/view/menu/ti;

    const-string v1, "flutter/isolate"

    invoke-virtual {p2, v1, v0}, Landroidx/appcompat/view/menu/ti;->a(Ljava/lang/String;Landroidx/appcompat/view/menu/h8$a;)V

    new-instance v0, Landroidx/appcompat/view/menu/ri$c;

    const/4 v1, 0x0

    invoke-direct {v0, p2, v1}, Landroidx/appcompat/view/menu/ri$c;-><init>(Landroidx/appcompat/view/menu/ti;Landroidx/appcompat/view/menu/ri$a;)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/ri;->d:Landroidx/appcompat/view/menu/h8;

    invoke-virtual {p1}, Lio/flutter/embedding/engine/FlutterJNI;->isAttached()Z

    move-result p1

    if-eqz p1, :cond_0

    const/4 p1, 0x1

    iput-boolean p1, p0, Landroidx/appcompat/view/menu/ri;->e:Z

    :cond_0
    return-void
.end method

.method public static synthetic c(Landroidx/appcompat/view/menu/ri;Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ri;->f:Ljava/lang/String;

    return-object p1
.end method

.method public static synthetic d(Landroidx/appcompat/view/menu/ri;)Landroidx/appcompat/view/menu/ri$d;
    .locals 0

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 p0, 0x0

    return-object p0
.end method


# virtual methods
.method public a(Ljava/lang/String;Landroidx/appcompat/view/menu/h8$a;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ri;->d:Landroidx/appcompat/view/menu/h8;

    invoke-interface {v0, p1, p2}, Landroidx/appcompat/view/menu/h8;->a(Ljava/lang/String;Landroidx/appcompat/view/menu/h8$a;)V

    return-void
.end method

.method public b(Ljava/lang/String;Ljava/nio/ByteBuffer;Landroidx/appcompat/view/menu/h8$b;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ri;->d:Landroidx/appcompat/view/menu/h8;

    invoke-interface {v0, p1, p2, p3}, Landroidx/appcompat/view/menu/h8;->b(Ljava/lang/String;Ljava/nio/ByteBuffer;Landroidx/appcompat/view/menu/h8$b;)V

    return-void
.end method

.method public e(Landroidx/appcompat/view/menu/ri$b;Ljava/util/List;)V
    .locals 9

    iget-boolean v0, p0, Landroidx/appcompat/view/menu/ri;->e:Z

    const-string v1, "DartExecutor"

    if-eqz v0, :cond_0

    const-string p1, "Attempted to run a DartExecutor that is already running."

    invoke-static {v1, p1}, Landroidx/appcompat/view/menu/ba0;->g(Ljava/lang/String;Ljava/lang/String;)V

    return-void

    :cond_0
    const-string v0, "DartExecutor#executeDartEntrypoint"

    invoke-static {v0}, Landroidx/appcompat/view/menu/l11;->i(Ljava/lang/String;)Landroidx/appcompat/view/menu/l11;

    move-result-object v0

    :try_start_0
    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Executing Dart entrypoint: "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v2

    invoke-static {v1, v2}, Landroidx/appcompat/view/menu/ba0;->f(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v3, p0, Landroidx/appcompat/view/menu/ri;->a:Lio/flutter/embedding/engine/FlutterJNI;

    iget-object v4, p1, Landroidx/appcompat/view/menu/ri$b;->a:Ljava/lang/String;

    iget-object v5, p1, Landroidx/appcompat/view/menu/ri$b;->c:Ljava/lang/String;

    iget-object v6, p1, Landroidx/appcompat/view/menu/ri$b;->b:Ljava/lang/String;

    iget-object v7, p0, Landroidx/appcompat/view/menu/ri;->b:Landroid/content/res/AssetManager;

    move-object v8, p2

    invoke-virtual/range {v3 .. v8}, Lio/flutter/embedding/engine/FlutterJNI;->runBundleAndSnapshotFromLibrary(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Landroid/content/res/AssetManager;Ljava/util/List;)V

    const/4 p1, 0x1

    iput-boolean p1, p0, Landroidx/appcompat/view/menu/ri;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v0, :cond_1

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/l11;->close()V

    :cond_1
    return-void

    :catchall_0
    move-exception p1

    if-eqz v0, :cond_2

    :try_start_1
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/l11;->close()V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    goto :goto_0

    :catchall_1
    move-exception p2

    invoke-virtual {p1, p2}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    :cond_2
    :goto_0
    throw p1
.end method

.method public f()Landroidx/appcompat/view/menu/h8;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ri;->d:Landroidx/appcompat/view/menu/h8;

    return-object v0
.end method

.method public g()Z
    .locals 1

    iget-boolean v0, p0, Landroidx/appcompat/view/menu/ri;->e:Z

    return v0
.end method

.method public h()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/ri;->a:Lio/flutter/embedding/engine/FlutterJNI;

    invoke-virtual {v0}, Lio/flutter/embedding/engine/FlutterJNI;->isAttached()Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/ri;->a:Lio/flutter/embedding/engine/FlutterJNI;

    invoke-virtual {v0}, Lio/flutter/embedding/engine/FlutterJNI;->notifyLowMemoryWarning()V

    :cond_0
    return-void
.end method

.method public i()V
    .locals 2

    const-string v0, "DartExecutor"

    const-string v1, "Attached to JNI. Registering the platform message handler for this Dart execution context."

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/ba0;->f(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/ri;->a:Lio/flutter/embedding/engine/FlutterJNI;

    iget-object v1, p0, Landroidx/appcompat/view/menu/ri;->c:Landroidx/appcompat/view/menu/ti;

    invoke-virtual {v0, v1}, Lio/flutter/embedding/engine/FlutterJNI;->setPlatformMessageHandler(Landroidx/appcompat/view/menu/ei0;)V

    return-void
.end method

.method public j()V
    .locals 2

    const-string v0, "DartExecutor"

    const-string v1, "Detached from JNI. De-registering the platform message handler for this Dart execution context."

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/ba0;->f(Ljava/lang/String;Ljava/lang/String;)V

    iget-object v0, p0, Landroidx/appcompat/view/menu/ri;->a:Lio/flutter/embedding/engine/FlutterJNI;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Lio/flutter/embedding/engine/FlutterJNI;->setPlatformMessageHandler(Landroidx/appcompat/view/menu/ei0;)V

    return-void
.end method
