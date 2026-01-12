.class public final Landroidx/appcompat/view/menu/g5$e;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/pf0;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/g5;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "e"
.end annotation


# static fields
.field public static final a:Landroidx/appcompat/view/menu/g5$e;

.field public static final b:Landroidx/appcompat/view/menu/mr;

.field public static final c:Landroidx/appcompat/view/menu/mr;

.field public static final d:Landroidx/appcompat/view/menu/mr;

.field public static final e:Landroidx/appcompat/view/menu/mr;

.field public static final f:Landroidx/appcompat/view/menu/mr;

.field public static final g:Landroidx/appcompat/view/menu/mr;

.field public static final h:Landroidx/appcompat/view/menu/mr;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/g5$e;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/g5$e;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/g5$e;->a:Landroidx/appcompat/view/menu/g5$e;

    const-string v0, "requestTimeMs"

    invoke-static {v0}, Landroidx/appcompat/view/menu/mr;->d(Ljava/lang/String;)Landroidx/appcompat/view/menu/mr;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/g5$e;->b:Landroidx/appcompat/view/menu/mr;

    const-string v0, "requestUptimeMs"

    invoke-static {v0}, Landroidx/appcompat/view/menu/mr;->d(Ljava/lang/String;)Landroidx/appcompat/view/menu/mr;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/g5$e;->c:Landroidx/appcompat/view/menu/mr;

    const-string v0, "clientInfo"

    invoke-static {v0}, Landroidx/appcompat/view/menu/mr;->d(Ljava/lang/String;)Landroidx/appcompat/view/menu/mr;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/g5$e;->d:Landroidx/appcompat/view/menu/mr;

    const-string v0, "logSource"

    invoke-static {v0}, Landroidx/appcompat/view/menu/mr;->d(Ljava/lang/String;)Landroidx/appcompat/view/menu/mr;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/g5$e;->e:Landroidx/appcompat/view/menu/mr;

    const-string v0, "logSourceName"

    invoke-static {v0}, Landroidx/appcompat/view/menu/mr;->d(Ljava/lang/String;)Landroidx/appcompat/view/menu/mr;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/g5$e;->f:Landroidx/appcompat/view/menu/mr;

    const-string v0, "logEvent"

    invoke-static {v0}, Landroidx/appcompat/view/menu/mr;->d(Ljava/lang/String;)Landroidx/appcompat/view/menu/mr;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/g5$e;->g:Landroidx/appcompat/view/menu/mr;

    const-string v0, "qosTier"

    invoke-static {v0}, Landroidx/appcompat/view/menu/mr;->d(Ljava/lang/String;)Landroidx/appcompat/view/menu/mr;

    move-result-object v0

    sput-object v0, Landroidx/appcompat/view/menu/g5$e;->h:Landroidx/appcompat/view/menu/mr;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public bridge synthetic a(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    check-cast p1, Landroidx/appcompat/view/menu/ea0;

    check-cast p2, Landroidx/appcompat/view/menu/qf0;

    invoke-virtual {p0, p1, p2}, Landroidx/appcompat/view/menu/g5$e;->b(Landroidx/appcompat/view/menu/ea0;Landroidx/appcompat/view/menu/qf0;)V

    return-void
.end method

.method public b(Landroidx/appcompat/view/menu/ea0;Landroidx/appcompat/view/menu/qf0;)V
    .locals 3

    sget-object v0, Landroidx/appcompat/view/menu/g5$e;->b:Landroidx/appcompat/view/menu/mr;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ea0;->g()J

    move-result-wide v1

    invoke-interface {p2, v0, v1, v2}, Landroidx/appcompat/view/menu/qf0;->b(Landroidx/appcompat/view/menu/mr;J)Landroidx/appcompat/view/menu/qf0;

    sget-object v0, Landroidx/appcompat/view/menu/g5$e;->c:Landroidx/appcompat/view/menu/mr;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ea0;->h()J

    move-result-wide v1

    invoke-interface {p2, v0, v1, v2}, Landroidx/appcompat/view/menu/qf0;->b(Landroidx/appcompat/view/menu/mr;J)Landroidx/appcompat/view/menu/qf0;

    sget-object v0, Landroidx/appcompat/view/menu/g5$e;->d:Landroidx/appcompat/view/menu/mr;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ea0;->b()Landroidx/appcompat/view/menu/xb;

    move-result-object v1

    invoke-interface {p2, v0, v1}, Landroidx/appcompat/view/menu/qf0;->e(Landroidx/appcompat/view/menu/mr;Ljava/lang/Object;)Landroidx/appcompat/view/menu/qf0;

    sget-object v0, Landroidx/appcompat/view/menu/g5$e;->e:Landroidx/appcompat/view/menu/mr;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ea0;->d()Ljava/lang/Integer;

    move-result-object v1

    invoke-interface {p2, v0, v1}, Landroidx/appcompat/view/menu/qf0;->e(Landroidx/appcompat/view/menu/mr;Ljava/lang/Object;)Landroidx/appcompat/view/menu/qf0;

    sget-object v0, Landroidx/appcompat/view/menu/g5$e;->f:Landroidx/appcompat/view/menu/mr;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ea0;->e()Ljava/lang/String;

    move-result-object v1

    invoke-interface {p2, v0, v1}, Landroidx/appcompat/view/menu/qf0;->e(Landroidx/appcompat/view/menu/mr;Ljava/lang/Object;)Landroidx/appcompat/view/menu/qf0;

    sget-object v0, Landroidx/appcompat/view/menu/g5$e;->g:Landroidx/appcompat/view/menu/mr;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ea0;->c()Ljava/util/List;

    move-result-object v1

    invoke-interface {p2, v0, v1}, Landroidx/appcompat/view/menu/qf0;->e(Landroidx/appcompat/view/menu/mr;Ljava/lang/Object;)Landroidx/appcompat/view/menu/qf0;

    sget-object v0, Landroidx/appcompat/view/menu/g5$e;->h:Landroidx/appcompat/view/menu/mr;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/ea0;->f()Landroidx/appcompat/view/menu/pl0;

    move-result-object p1

    invoke-interface {p2, v0, p1}, Landroidx/appcompat/view/menu/qf0;->e(Landroidx/appcompat/view/menu/mr;Ljava/lang/Object;)Landroidx/appcompat/view/menu/qf0;

    return-void
.end method
