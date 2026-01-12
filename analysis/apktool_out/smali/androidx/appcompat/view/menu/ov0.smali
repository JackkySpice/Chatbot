.class public Landroidx/appcompat/view/menu/ov0;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/ov0$a;
    }
.end annotation


# static fields
.field public static final b:Ljava/util/concurrent/atomic/AtomicBoolean;


# instance fields
.field public final a:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    sput-object v0, Landroidx/appcompat/view/menu/ov0;->b:Ljava/util/concurrent/atomic/AtomicBoolean;

    return-void
.end method

.method public constructor <init>()V
    .locals 1

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    return-void
.end method

.method public static a()Landroidx/appcompat/view/menu/ov0;
    .locals 1

    sget-object v0, Landroidx/appcompat/view/menu/ov0$a;->a:Landroidx/appcompat/view/menu/ov0;

    return-object v0
.end method


# virtual methods
.method public b()V
    .locals 5

    sget-object v0, Landroidx/appcompat/view/menu/ov0;->b:Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 v1, 0x1

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicBoolean;->getAndSet(Z)Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    :cond_0
    invoke-static {}, Landroidx/appcompat/view/menu/hv0;->x()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    invoke-static {}, Landroidx/appcompat/view/menu/w6;->w2()Landroidx/appcompat/view/menu/w6;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    invoke-static {}, Landroidx/appcompat/view/menu/e7;->k()Landroidx/appcompat/view/menu/e7;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    invoke-static {}, Landroidx/appcompat/view/menu/av0;->h()Landroidx/appcompat/view/menu/av0;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    invoke-static {}, Landroidx/appcompat/view/menu/n6;->k()Landroidx/appcompat/view/menu/n6;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    invoke-static {}, Landroidx/appcompat/view/menu/a7;->h()Landroidx/appcompat/view/menu/a7;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    invoke-static {}, Landroidx/appcompat/view/menu/v6;->h()Landroidx/appcompat/view/menu/v6;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    invoke-static {}, Landroidx/appcompat/view/menu/z6;->e()Landroidx/appcompat/view/menu/z6;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    invoke-static {}, Landroidx/appcompat/view/menu/xu0;->I2()Landroidx/appcompat/view/menu/xu0;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    invoke-static {}, Landroidx/appcompat/view/menu/s6;->w2()Landroidx/appcompat/view/menu/s6;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    invoke-static {}, Landroidx/appcompat/view/menu/lv0;->k()Landroidx/appcompat/view/menu/lv0;

    move-result-object v1

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    iget-object v0, p0, Landroidx/appcompat/view/menu/ov0;->a:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Landroidx/appcompat/view/menu/k30;

    invoke-interface {v1}, Landroidx/appcompat/view/menu/k30;->j()V

    goto :goto_0

    :cond_1
    invoke-static {}, Landroidx/appcompat/view/menu/x3;->a()Ljava/util/List;

    move-result-object v0

    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :catch_0
    :cond_2
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/lang/String;

    :try_start_0
    invoke-static {}, Landroidx/appcompat/view/menu/w6;->w2()Landroidx/appcompat/view/menu/w6;

    move-result-object v2

    const/4 v3, -0x1

    invoke-virtual {v2, v1, v3}, Landroidx/appcompat/view/menu/w6;->F1(Ljava/lang/String;I)Z

    move-result v2

    if-nez v2, :cond_2

    invoke-static {}, Landroidx/appcompat/view/menu/uu0;->r()Landroid/content/pm/PackageManager;

    move-result-object v2

    const/4 v4, 0x0

    invoke-virtual {v2, v1, v4}, Landroid/content/pm/PackageManager;->getPackageInfo(Ljava/lang/String;I)Landroid/content/pm/PackageInfo;

    move-result-object v1

    invoke-static {}, Landroidx/appcompat/view/menu/w6;->w2()Landroidx/appcompat/view/menu/w6;

    move-result-object v2

    iget-object v1, v1, Landroid/content/pm/PackageInfo;->applicationInfo:Landroid/content/pm/ApplicationInfo;

    iget-object v1, v1, Landroid/content/pm/ApplicationInfo;->sourceDir:Ljava/lang/String;

    invoke-static {}, Landroidx/appcompat/view/menu/l50;->a()Landroidx/appcompat/view/menu/l50;

    move-result-object v4

    invoke-virtual {v2, v1, v4, v3}, Landroidx/appcompat/view/menu/w6;->U0(Ljava/lang/String;Landroidx/appcompat/view/menu/l50;I)Landroidx/appcompat/view/menu/m50;
    :try_end_0
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :cond_3
    return-void
.end method
