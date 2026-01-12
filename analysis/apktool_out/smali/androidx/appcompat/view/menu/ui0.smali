.class public Landroidx/appcompat/view/menu/ui0;
.super Ljava/lang/Object;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/ui0$g;,
        Landroidx/appcompat/view/menu/ui0$f;,
        Landroidx/appcompat/view/menu/ui0$b;,
        Landroidx/appcompat/view/menu/ui0$c;,
        Landroidx/appcompat/view/menu/ui0$e;,
        Landroidx/appcompat/view/menu/ui0$d;
    }
.end annotation


# instance fields
.field public final a:Landroidx/appcompat/view/menu/hd0;

.field public b:Landroidx/appcompat/view/menu/ui0$g;

.field public final c:Landroidx/appcompat/view/menu/hd0$c;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ri;)V
    .locals 4

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Landroidx/appcompat/view/menu/ui0$a;

    invoke-direct {v0, p0}, Landroidx/appcompat/view/menu/ui0$a;-><init>(Landroidx/appcompat/view/menu/ui0;)V

    iput-object v0, p0, Landroidx/appcompat/view/menu/ui0;->c:Landroidx/appcompat/view/menu/hd0$c;

    new-instance v1, Landroidx/appcompat/view/menu/hd0;

    const-string v2, "flutter/platform_views"

    sget-object v3, Landroidx/appcompat/view/menu/mw0;->b:Landroidx/appcompat/view/menu/mw0;

    invoke-direct {v1, p1, v2, v3}, Landroidx/appcompat/view/menu/hd0;-><init>(Landroidx/appcompat/view/menu/h8;Ljava/lang/String;Landroidx/appcompat/view/menu/id0;)V

    iput-object v1, p0, Landroidx/appcompat/view/menu/ui0;->a:Landroidx/appcompat/view/menu/hd0;

    invoke-virtual {v1, v0}, Landroidx/appcompat/view/menu/hd0;->e(Landroidx/appcompat/view/menu/hd0$c;)V

    return-void
.end method

.method public static synthetic a(Landroidx/appcompat/view/menu/ui0;)Landroidx/appcompat/view/menu/ui0$g;
    .locals 0

    iget-object p0, p0, Landroidx/appcompat/view/menu/ui0;->b:Landroidx/appcompat/view/menu/ui0$g;

    return-object p0
.end method

.method public static synthetic b(Ljava/lang/Exception;)Ljava/lang/String;
    .locals 0

    invoke-static {p0}, Landroidx/appcompat/view/menu/ui0;->c(Ljava/lang/Exception;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method public static c(Ljava/lang/Exception;)Ljava/lang/String;
    .locals 0

    invoke-static {p0}, Landroidx/appcompat/view/menu/ba0;->d(Ljava/lang/Throwable;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public d(Landroidx/appcompat/view/menu/ui0$g;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/ui0;->b:Landroidx/appcompat/view/menu/ui0$g;

    return-void
.end method
