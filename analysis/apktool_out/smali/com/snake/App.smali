.class public Lcom/snake/App;
.super Landroid/app/Application;
.source "SourceFile"


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Ljava/lang/String;

    const/4 v1, 0x6

    new-array v1, v1, [B

    fill-array-data v1, :array_0

    invoke-direct {v0, v1}, Ljava/lang/String;-><init>([B)V

    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    return-void

    nop

    :array_0
    .array-data 1
        0x65t
        0x6et
        0x67t
        0x69t
        0x6et
        0x65t
    .end array-data
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Landroid/app/Application;-><init>()V

    return-void
.end method


# virtual methods
.method public attachBaseContext(Landroid/content/Context;)V
    .locals 2

    invoke-super {p0, p1}, Landroid/content/ContextWrapper;->attachBaseContext(Landroid/content/Context;)V

    :try_start_0
    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->g()Landroidx/appcompat/view/menu/uu0;

    move-result-object v0

    new-instance v1, Lcom/snake/App$a;

    invoke-direct {v1, p0, p1}, Lcom/snake/App$a;-><init>(Lcom/snake/App;Landroid/content/Context;)V

    invoke-virtual {v0, p1, v1}, Landroidx/appcompat/view/menu/uu0;->e(Landroid/content/Context;Landroidx/appcompat/view/menu/vb;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    invoke-virtual {p1}, Ljava/lang/Throwable;->printStackTrace()V

    const/4 p1, 0x0

    invoke-static {p1}, Ljava/lang/System;->exit(I)V

    :goto_0
    return-void
.end method

.method public onCreate()V
    .locals 1

    invoke-super {p0}, Landroid/app/Application;->onCreate()V

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->g()Landroidx/appcompat/view/menu/uu0;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/uu0;->f()V

    return-void
.end method
