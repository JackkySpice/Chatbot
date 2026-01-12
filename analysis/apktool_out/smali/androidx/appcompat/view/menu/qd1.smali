.class public final Landroidx/appcompat/view/menu/qd1;
.super Landroidx/appcompat/view/menu/zx;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/jz0;


# static fields
.field public static final k:Landroidx/appcompat/view/menu/l2$g;

.field public static final l:Landroidx/appcompat/view/menu/l2$a;

.field public static final m:Landroidx/appcompat/view/menu/l2;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    new-instance v0, Landroidx/appcompat/view/menu/l2$g;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/l2$g;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/qd1;->k:Landroidx/appcompat/view/menu/l2$g;

    new-instance v1, Landroidx/appcompat/view/menu/od1;

    invoke-direct {v1}, Landroidx/appcompat/view/menu/od1;-><init>()V

    sput-object v1, Landroidx/appcompat/view/menu/qd1;->l:Landroidx/appcompat/view/menu/l2$a;

    new-instance v2, Landroidx/appcompat/view/menu/l2;

    const-string v3, "ClientTelemetry.API"

    invoke-direct {v2, v3, v1, v0}, Landroidx/appcompat/view/menu/l2;-><init>(Ljava/lang/String;Landroidx/appcompat/view/menu/l2$a;Landroidx/appcompat/view/menu/l2$g;)V

    sput-object v2, Landroidx/appcompat/view/menu/qd1;->m:Landroidx/appcompat/view/menu/l2;

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroidx/appcompat/view/menu/kz0;)V
    .locals 2

    sget-object v0, Landroidx/appcompat/view/menu/qd1;->m:Landroidx/appcompat/view/menu/l2;

    sget-object v1, Landroidx/appcompat/view/menu/zx$a;->c:Landroidx/appcompat/view/menu/zx$a;

    invoke-direct {p0, p1, v0, p2, v1}, Landroidx/appcompat/view/menu/zx;-><init>(Landroid/content/Context;Landroidx/appcompat/view/menu/l2;Landroidx/appcompat/view/menu/l2$d;Landroidx/appcompat/view/menu/zx$a;)V

    return-void
.end method


# virtual methods
.method public final a(Landroidx/appcompat/view/menu/hz0;)Landroidx/appcompat/view/menu/vy0;
    .locals 4

    invoke-static {}, Landroidx/appcompat/view/menu/wy0;->a()Landroidx/appcompat/view/menu/wy0$a;

    move-result-object v0

    const/4 v1, 0x1

    new-array v1, v1, [Landroidx/appcompat/view/menu/lr;

    sget-object v2, Landroidx/appcompat/view/menu/mc1;->a:Landroidx/appcompat/view/menu/lr;

    const/4 v3, 0x0

    aput-object v2, v1, v3

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/wy0$a;->d([Landroidx/appcompat/view/menu/lr;)Landroidx/appcompat/view/menu/wy0$a;

    invoke-virtual {v0, v3}, Landroidx/appcompat/view/menu/wy0$a;->c(Z)Landroidx/appcompat/view/menu/wy0$a;

    new-instance v1, Landroidx/appcompat/view/menu/ld1;

    invoke-direct {v1, p1}, Landroidx/appcompat/view/menu/ld1;-><init>(Landroidx/appcompat/view/menu/hz0;)V

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/wy0$a;->b(Landroidx/appcompat/view/menu/jo0;)Landroidx/appcompat/view/menu/wy0$a;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/wy0$a;->a()Landroidx/appcompat/view/menu/wy0;

    move-result-object p1

    invoke-virtual {p0, p1}, Landroidx/appcompat/view/menu/zx;->c(Landroidx/appcompat/view/menu/wy0;)Landroidx/appcompat/view/menu/vy0;

    move-result-object p1

    return-object p1
.end method
