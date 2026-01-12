.class public final Landroidx/appcompat/view/menu/i5;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/af;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Landroidx/appcompat/view/menu/i5$a;,
        Landroidx/appcompat/view/menu/i5$b;,
        Landroidx/appcompat/view/menu/i5$c;
    }
.end annotation


# static fields
.field public static final a:Landroidx/appcompat/view/menu/af;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Landroidx/appcompat/view/menu/i5;

    invoke-direct {v0}, Landroidx/appcompat/view/menu/i5;-><init>()V

    sput-object v0, Landroidx/appcompat/view/menu/i5;->a:Landroidx/appcompat/view/menu/af;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a(Landroidx/appcompat/view/menu/jo;)V
    .locals 2

    const-class v0, Landroidx/appcompat/view/menu/qk0;

    sget-object v1, Landroidx/appcompat/view/menu/i5$c;->a:Landroidx/appcompat/view/menu/i5$c;

    invoke-interface {p1, v0, v1}, Landroidx/appcompat/view/menu/jo;->a(Ljava/lang/Class;Landroidx/appcompat/view/menu/pf0;)Landroidx/appcompat/view/menu/jo;

    const-class v0, Landroidx/appcompat/view/menu/yc0;

    sget-object v1, Landroidx/appcompat/view/menu/i5$b;->a:Landroidx/appcompat/view/menu/i5$b;

    invoke-interface {p1, v0, v1}, Landroidx/appcompat/view/menu/jo;->a(Ljava/lang/Class;Landroidx/appcompat/view/menu/pf0;)Landroidx/appcompat/view/menu/jo;

    const-class v0, Landroidx/appcompat/view/menu/xc0;

    sget-object v1, Landroidx/appcompat/view/menu/i5$a;->a:Landroidx/appcompat/view/menu/i5$a;

    invoke-interface {p1, v0, v1}, Landroidx/appcompat/view/menu/jo;->a(Ljava/lang/Class;Landroidx/appcompat/view/menu/pf0;)Landroidx/appcompat/view/menu/jo;

    return-void
.end method
